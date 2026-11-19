//! Supplies a configuration datastore and the local services of the host.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;

use tacacsrs_composition::{Component, Composition};
use tacacsrs_config::input::{immutable_cli_tacacs_plus, CliDatastoreInput};
use tacacsrs_config::local_services::{parse_local_services, LocalServicesPatch};
use tacacsrs_config::source::{CliFileDatastore, ConfigDatastore};
use tacacsrs_config::tacacsrs::LocalServices;
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
/// Preparation rejects invalid command-line server values and reads the local
/// services. Preparation does not read the datastore. The configuration
/// supervisor reads the datastore after startup, and runtime health reports
/// each rejected configuration.
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
    /// Preparation validates the command-line server values.
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
        if let Some(input) = &self.cli_input {
            immutable_cli_tacacs_plus(input)
                .context("The command-line server configuration is invalid")?;
        }
        self.local_services = Some(self.local_services_input.resolve().await?);
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
    async fn preparation_does_not_read_the_datastore() {
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

        // The runtime rejects the looping server after startup. Runtime health
        // reports the rejection.
        component("127.0.0.1:9049").prepare().await.unwrap();
        component("192.0.2.20:9049").prepare().await.unwrap();
    }
}
