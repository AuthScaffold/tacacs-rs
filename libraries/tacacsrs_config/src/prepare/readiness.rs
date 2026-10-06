//! Shared schema and capability checks before runtime publication.

use anyhow::{ensure, Context};

use crate::{TacacsPlusServer, ValidationOptions};
use crate::crypto_types::SymmetricKeyFormat;

/// Validates a complete materialized server set with the source's schema policy.
///
/// An empty set is valid for a runtime that waits for configuration. This does
/// not relax the nonempty server-list constraint for parsed YANG documents.
/// Native context construction must also succeed before publication.
///
/// # Errors
///
/// Returns an error for invalid schema choices, duplicate names or endpoints,
/// unresolved credentials, or unsupported runtime fields.
pub fn validate_materialized_servers<'a>(
    servers: impl IntoIterator<Item = &'a TacacsPlusServer>,
    options: &ValidationOptions,
) -> anyhow::Result<()> {
    let servers = servers.into_iter().collect::<Vec<_>>();
    crate::validation::validate_server_set(servers.iter().copied(), options)?;
    for server in servers {
        validate_runtime_features(server)?;
    }
    Ok(())
}

pub(super) fn validate_runtime_features(server: &TacacsPlusServer) -> anyhow::Result<()> {
    let references = crate::inspect_central_references(server)
        .context("Expand credential bundles before endpoint preparation")?;
    ensure!(references.is_empty(), "Resolve central credentials before endpoint preparation");
    ensure!(server.source_ip.is_none(), "source-ip is not supported by the client transport");
    ensure!(
        server.source_interface.is_none(),
        "source-interface is not supported by the client transport"
    );
    ensure!(server.vrf_instance.is_none(), "vrf-instance is not supported by the client transport");
    if let Some(epsk) = server
        .client_identity
        .as_ref()
        .and_then(|identity| identity.tls13_epsk.as_ref())
    {
        crate::validation::reject_unsupported_epsk_derivation(&server.name, epsk)?;
        let format = epsk
            .inline_definition
            .as_ref()
            .and_then(|inline| inline.key_format);
        ensure!(
            format != Some(SymmetricKeyFormat::OneSymmetricKeyFormat),
            "TLS PSK one-symmetric-key-format is not supported by the client transport"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TacacsPlusServerBuilder, TacacsPlusServerType, ValidationRelaxation};

    fn server() -> TacacsPlusServer {
        TacacsPlusServerBuilder::new("primary", TacacsPlusServerType::all(), "192.0.2.1", 49)
            .with_shared_secret("test-secret")
            .build()
    }

    #[test]
    fn policy_relaxation_is_explicit_and_cannot_enable_unsupported_transport_fields() {
        let mut server = server();
        server.shared_secret = None;
        assert!(validate_materialized_servers([&server], &ValidationOptions::default()).is_err());
        let options = ValidationOptions::new()
            .with_relaxation(ValidationRelaxation::AllowPlainTcpWithoutSharedSecret);
        validate_materialized_servers([&server], &options).unwrap();
        server.source_interface = Some("private-interface".to_owned());
        let error = validate_materialized_servers([&server], &options).unwrap_err();
        assert!(error.to_string().contains("source-interface"));
        assert!(!format!("{error:#}").contains("private-interface"));
    }

    #[test]
    fn duplicate_server_names_fail_before_publication() {
        let first = server();
        let mut second = first.clone();
        second.address = "192.0.2.2".to_owned();
        assert!(validate_materialized_servers([&first, &second], &ValidationOptions::default())
            .is_err());
    }

    #[test]
    fn empty_runtime_set_is_valid() {
        validate_materialized_servers([], &ValidationOptions::default()).unwrap();
    }

    #[test]
    fn unsupported_fields_fail_direct_preparation_without_changing_the_source() {
        use tacacsrs_networking::ConnectOptions;

        for field in [
            "source-ip",
            "source-interface",
            "vrf-instance",
            "context",
            "target-protocol",
            "target-kdf",
            "one-symmetric-key-format",
        ] {
            let mut server = TacacsPlusServerBuilder::new(
                "primary",
                TacacsPlusServerType::all(),
                "192.0.2.1",
                449,
            )
            .with_tls13_epsk_psk_only("client", b"protected-psk-material".to_vec())
            .build();
            let epsk = server
                .client_identity
                .as_mut()
                .unwrap()
                .tls13_epsk
                .as_mut()
                .unwrap();
            match field {
                "source-ip" => server.source_ip = Some("192.0.2.200".to_owned()),
                "source-interface" => server.source_interface = Some("private-source".to_owned()),
                "vrf-instance" => server.vrf_instance = Some("private-source".to_owned()),
                "context" => epsk.context = Some("private-source".to_owned()),
                "target-protocol" => epsk.target_protocol = Some(7),
                "target-kdf" => epsk.target_kdf = Some(1),
                "one-symmetric-key-format" => {
                    epsk.inline_definition.as_mut().unwrap().key_format =
                        Some(SymmetricKeyFormat::OneSymmetricKeyFormat);
                }
                _ => unreachable!(),
            }
            let original = server.clone();
            let error =
                super::super::prepare_endpoint(&server, ConnectOptions::default()).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(field));
            assert!(!message.contains("private-source"));
            assert!(!message.contains("protected-psk-material"));
            assert!(!message.contains("192.0.2.200"));
            assert_eq!(server, original);
        }
    }
}
