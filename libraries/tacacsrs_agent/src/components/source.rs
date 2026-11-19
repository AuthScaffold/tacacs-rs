//! Supplies a configuration datastore and the local services of the host.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;

use tacacsrs_composition::{Component, Composition};
use tacacsrs_config::input::{immutable_cli_tacacs_plus, CliDatastoreInput};
use tacacsrs_config::local_services::{parse_local_services, LocalServicesPatch};
use tacacsrs_config::source::{ChangeNotificationMode, CliFileDatastore, ConfigDatastore};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_config::TacacsPlus;
use tacacsrs_provider::{CredentialProvider, SourceDatastore};

/// The origin of the local services of a [`DatastoreSourceComponent`].
#[derive(Debug, Clone)]
pub enum LocalServicesInput {
    /// Uses the given value.
    Fixed(LocalServices),
    /// Reads a `tacacsrs:local-services` YANG JSON resource from the file.
    File(PathBuf),
    /// Applies the patch to the default local services.
    Patch(LocalServicesPatch),
}

impl LocalServicesInput {
    /// Resolves the local services.
    ///
    /// # Errors
    /// Returns an error for an unreadable file or an invalid result.
    pub async fn resolve(&self) -> anyhow::Result<LocalServices> {
        match self {
            Self::Fixed(services) => Ok(services.clone()),
            Self::File(path) => {
                let bytes = tokio::fs::read(path)
                    .await
                    .with_context(|| format!("read local-services resource {}", path.display()))?;
                parse_local_services(&bytes)
            }
            Self::Patch(patch) => patch.apply(LocalServices::default()),
        }
    }
}

/// Supplies a datastore, no source credentials, and the local services.
///
/// Preparation rejects invalid command-line server values, because they
/// cannot change later. Preparation also loads an unwatched datastore once. A
/// watched file can change later, so the runtime retries a file error.
pub struct DatastoreSourceComponent {
    name: &'static str,
    datastore: Arc<dyn ConfigDatastore>,
    cli_input: Option<CliDatastoreInput>,
    local_services_input: LocalServicesInput,
    local_services: Option<LocalServices>,
}

impl DatastoreSourceComponent {
    /// Creates a source for any datastore.
    #[must_use]
    pub fn new(
        name: &'static str,
        datastore: Arc<dyn ConfigDatastore>,
        local_services: LocalServicesInput,
    ) -> Self {
        Self {
            name,
            datastore,
            cli_input: None,
            local_services_input: local_services,
            local_services: None,
        }
    }

    /// Creates a source for a file datastore with command-line server values.
    ///
    /// Preparation validates the command-line server values. For inline
    /// servers with IP-literal addresses, preparation also applies the proxy
    /// policy of the local services, because neither value can change later.
    #[must_use]
    pub fn from_file_datastore(
        name: &'static str,
        datastore: Arc<CliFileDatastore>,
        local_services: LocalServicesInput,
    ) -> Self {
        Self {
            name,
            cli_input: Some(datastore.input().clone()),
            datastore,
            local_services_input: local_services,
            local_services: None,
        }
    }
}

#[async_trait::async_trait]
impl Component for DatastoreSourceComponent {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn prepare(&mut self) -> anyhow::Result<()> {
        let mut immutable = match &self.cli_input {
            Some(input) => immutable_cli_tacacs_plus(input)
                .context("The command-line server configuration is invalid")?,
            None => None,
        };
        // Immutable input cannot recover later, so a load error is an operator input error.
        if self.datastore.runtime_policy().change_notifications == ChangeNotificationMode::None {
            immutable = Some(
                self.datastore
                    .load()
                    .await
                    .context("The command-line server configuration is invalid")?,
            );
        }
        let local_services = self.local_services_input.resolve().await?;
        if let Some(servers) = immutable {
            check_immutable_proxy_policy(&local_services, servers)
                .await
                .context("The server configuration conflicts with the local services")?;
        }
        self.local_services = Some(local_services);
        Ok(())
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let local_services = self
            .local_services
            .context("The local services are not prepared")?;
        composition.shared(Arc::new(SourceDatastore(self.datastore)))?;
        composition.shared(Arc::new(CredentialProvider::none()))?;
        composition.shared(Arc::new(local_services))
    }
}

/// Applies the proxy policy of `local_services` to a server set that cannot change.
///
/// The check runs only when every server address is an IP literal. A host
/// name needs DNS, and a DNS result can change, so runtime health reports
/// those conflicts. A conflict in an IP-literal set cannot recover, because
/// the server set and the local services are fixed for the process.
async fn check_immutable_proxy_policy(
    local_services: &LocalServices,
    servers: TacacsPlus,
) -> anyhow::Result<()> {
    if servers
        .server
        .iter()
        .any(|server| server.address.parse::<std::net::IpAddr>().is_err())
    {
        return Ok(());
    }
    let configured = servers.server.len();
    let filtered = crate::runtime::config_filter_from_local_services(local_services)?
        .filter(servers)
        .await?;
    anyhow::ensure!(
        configured == 0 || !filtered.tacacs_plus.server.is_empty(),
        "Every upstream server targets the local TACACS+ proxy endpoint"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_input_loads_the_canonical_resource_and_rejects_invalid_values() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("local-services-{}-{unique}.json", std::process::id()));
        let input = LocalServicesInput::File(path.clone());
        let document = br#"{"tacacsrs:local-services":{"client-api-endpoint":"/tmp/file-api.sock","unix-socket-mode":384}}"#;
        tokio::fs::write(&path, document).await.unwrap();
        let source = input.resolve().await.unwrap();
        assert_eq!(source, parse_local_services(document).unwrap());
        tokio::fs::write(&path, br#"{"tacacsrs:local-services":{"unix-socket-mode":512}}"#)
            .await
            .unwrap();
        let invalid = input.resolve().await;
        tokio::fs::remove_file(&path).await.unwrap();
        assert!(invalid.is_err());
        assert_eq!(source.unix_socket_mode, 0o600);
    }

    #[tokio::test]
    async fn immutable_inline_servers_that_loop_into_the_proxy_fail_preparation() {
        use tacacsrs_config::input::{
            CertKeyIdentity, CliConfigSource, CliSecurity, CliSecurityMode, CliServerInput,
        };
        use tacacsrs_config::tacacsrs::ProxyCredentialSource;

        let component = |address: &str| {
            let input = CliDatastoreInput::new(
                CliConfigSource::Inline {
                    servers: vec![CliServerInput::new("upstream", address)],
                    security: CliSecurity {
                        mode: CliSecurityMode::TlsClientCertificate {
                            identity: CertKeyIdentity::new(
                                "/missing/client.crt",
                                "/missing/client.key",
                            ),
                        },
                        shared_secret: None,
                    },
                },
                "inline",
            );
            DatastoreSourceComponent::from_file_datastore(
                "Inline fixture",
                Arc::new(CliFileDatastore::new(input)),
                LocalServicesInput::Fixed(LocalServices {
                    tacacs_proxy_enabled: true,
                    tacacs_proxy_endpoint: Some("127.0.0.1:9049".to_owned()),
                    proxy_credential_source: ProxyCredentialSource::Unobfuscated,
                    ..LocalServices::default()
                }),
            )
        };

        let error = component("127.0.0.1:9049").prepare().await.unwrap_err();
        assert!(format!("{error:#}").contains("TLS upstream targets"), "{error:#}");
        component("192.0.2.20:9049").prepare().await.unwrap();
    }
}
