//! Runtime extraction and local-capability admission of configured servers.

use std::sync::Arc;

use tacacsrs_config::TacacsPlusServer;
#[cfg(test)]
use tacacsrs_config::TacacsPlusServerType;
use tacacsrs_networking::{LocalCapability, LocalCapabilityError};

use super::LocalCapabilityExclusion;

#[cfg(test)]
pub(crate) const REQUIRED_SERVER_TYPES: TacacsPlusServerType = TacacsPlusServerType::AUTHENTICATION
    .union(TacacsPlusServerType::AUTHORIZATION)
    .union(TacacsPlusServerType::ACCOUNTING);

pub(crate) fn enumerate_supported_servers(
    config: &tacacsrs_config::TacacsPlus,
) -> anyhow::Result<Vec<TacacsPlusServer>> {
    tacacsrs_config::enumerate_servers(config)
}

pub(crate) trait ServerCapabilityValidator: Send + Sync {
    fn validate(&self, server: &TacacsPlusServer) -> Result<(), LocalCapabilityError>;
}

pub(crate) struct OpenSslServerCapabilityValidator;

impl ServerCapabilityValidator for OpenSslServerCapabilityValidator {
    fn validate(&self, server: &TacacsPlusServer) -> Result<(), LocalCapabilityError> {
        tacacsrs_networking::validate_server_local_capabilities(server)
    }
}

pub(crate) struct ServerAdmission {
    pub(crate) admitted: Vec<Arc<TacacsPlusServer>>,
    pub(crate) exclusions: Vec<LocalCapabilityExclusion>,
}

pub(crate) fn admit_servers(
    servers: Vec<Arc<TacacsPlusServer>>,
    validator: &dyn ServerCapabilityValidator,
) -> ServerAdmission {
    let mut admitted = Vec::with_capacity(servers.len());
    let mut exclusions = Vec::new();

    for server in servers {
        match validator.validate(&server) {
            Ok(()) => admitted.push(server),
            Err(error) => {
                let exclusion = LocalCapabilityExclusion::new(
                    server.name.clone(),
                    map_capability(error.capability()),
                );
                log::error!(
                    "Excluded TACACS+ server {} from active routing: {error}",
                    exclusion.server_name()
                );
                exclusions.push(exclusion);
            }
        }
    }

    ServerAdmission {
        admitted,
        exclusions,
    }
}

const fn map_capability(capability: LocalCapability) -> super::RequiredLocalCapability {
    match capability {
        LocalCapability::Tls13Kdf => super::RequiredLocalCapability::OpenSslTls13Kdf,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tacacsrs_config::generated::tacacs_plus::{
        EpskSupportedHash, Tls13Epsk, TlsClientClientIdentity,
    };
    use tacacsrs_config::keystore::SymmetricKeyInlineDefinition;
    use tacacsrs_networking::LocalCapabilityError;
    use tacacsrs_secrets::SecretBytes;

    use super::*;
    use crate::EnabledServices;
    use crate::runtime::RuntimeHealthPublisher;
    use crate::test_support::FakeConnector;
    use crate::upstream::manager::UpstreamManager;

    struct TestValidator {
        calls: AtomicUsize,
        psk_supported: bool,
    }

    impl ServerCapabilityValidator for TestValidator {
        fn validate(&self, server: &TacacsPlusServer) -> Result<(), LocalCapabilityError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let has_psk = server
                .client_identity
                .as_ref()
                .is_some_and(|identity| identity.tls13_epsk.is_some());
            if self.psk_supported || !has_psk {
                return Ok(());
            }

            Err(LocalCapabilityError::tls13_kdf_unavailable())
        }
    }

    fn plain_server(name: &str) -> TacacsPlusServer {
        TacacsPlusServer {
            name: name.to_owned(),
            server_type: REQUIRED_SERVER_TYPES,
            address: "127.0.0.1".to_owned(),
            port: 49,
            shared_secret: None,
            timeout: 5,
            single_connection: false,
            domain_name: None,
            sni_enabled: None,
            source_interface: None,
            source_ip: None,
            vrf_instance: None,
            client_identity: None,
            server_authentication: None,
        }
    }

    fn psk_server(name: &str) -> TacacsPlusServer {
        let mut server = plain_server(name);
        server.client_identity = Some(TlsClientClientIdentity {
            certificate: None,
            tls13_epsk: Some(Tls13Epsk {
                external_identity: "client-id".to_owned(),
                hash: EpskSupportedHash::Sha256,
                context: None,
                target_protocol: None,
                target_kdf: None,
                psk_dhe_ke_groups: vec![],
                inline_definition: Some(SymmetricKeyInlineDefinition {
                    key_format: None,
                    cleartext_symmetric_key: Some(SecretBytes::new(vec![7; 16])),
                }),
                central_keystore_reference: None,
            }),
            credentials_reference: None,
        });
        server
    }

    #[test]
    fn admission_excludes_only_locally_unsupported_psk_servers() {
        let validator = TestValidator {
            calls: AtomicUsize::new(0),
            psk_supported: false,
        };
        let servers = vec![Arc::new(psk_server("psk")), Arc::new(plain_server("plain"))];

        let admission = admit_servers(servers, &validator);

        assert_eq!(admission.admitted.len(), 1);
        assert_eq!(admission.admitted[0].name, "plain");
        assert_eq!(admission.exclusions.len(), 1);
        assert_eq!(admission.exclusions[0].server_name(), "psk");
        assert_eq!(
            admission.exclusions[0].capability(),
            super::super::RequiredLocalCapability::OpenSslTls13Kdf
        );
    }

    #[test]
    fn admission_reevaluates_capabilities_for_each_configuration_generation() {
        let validator = TestValidator {
            calls: AtomicUsize::new(0),
            psk_supported: true,
        };

        for _ in 0..2 {
            let admission = admit_servers(vec![Arc::new(psk_server("psk"))], &validator);
            assert_eq!(admission.admitted.len(), 1);
        }

        assert_eq!(validator.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn excluded_psk_server_never_enters_connection_recovery() {
        let validator = TestValidator {
            calls: AtomicUsize::new(0),
            psk_supported: false,
        };
        let admission = admit_servers(vec![Arc::new(psk_server("psk"))], &validator);
        let connector = Arc::new(FakeConnector::new(HashMap::new()));
        let manager = UpstreamManager::new_shared(
            admission.admitted,
            Arc::clone(&connector) as Arc<dyn crate::upstream::UpstreamConnector>,
            std::time::Duration::from_secs(1),
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
        );

        for _ in 0..2 {
            assert!(manager.bind_server_for_new_session().await.is_err());
        }

        assert_eq!(connector.connect_attempts_for("127.0.0.1:49").await, 0);
    }
}
