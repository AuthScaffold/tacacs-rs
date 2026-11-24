//! Inline CLI server and transport registration.

use std::path::PathBuf;
use std::sync::Arc;

use tacacsrs_agent::components::DatastoreSourceComponent;
use tacacsrs_config::input::{
    CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs, CliServerInput,
};
use tacacsrs_config::source::CliFileDatastore;
use tacacsrs_config::input::{CliPskInputs, PskKeyExchangeMode, PskKeyMaterial};

use crate::cli::{Cli, PskKeyExchange};
use crate::local_services;
use super::SelectedProfile;

fn cli_datastore_input_from_cli(cli: &Cli) -> CliDatastoreInput {
    let timeout = u16::try_from(cli.connect_timeout_seconds).unwrap_or(u16::MAX);
    let servers = cli
        .server_addresses
        .iter()
        .enumerate()
        .map(|(index, address)| {
            CliServerInput::new(format!("server-{index}"), address.clone())
                .with_timeout_seconds(timeout)
                .with_single_connection(!cli.dedicated)
        })
        .collect();

    CliDatastoreInput::new(
        CliConfigSource::Inline {
            servers,
            security: cli_security_from_cli(cli),
        },
        "cli",
    )
}

fn cli_security_from_cli(cli: &Cli) -> CliSecurity {
    CliSecurity::from_cli_inputs(CliSecurityInputs {
        use_tls: cli.use_tls,
        shared_secret: cli
            .shared_secret
            .as_ref()
            .map(|secret| secret.expose_secret().to_owned()),
        client_certificate: cli.client_certificate.clone().map(PathBuf::from),
        client_key: cli.client_key.clone().map(PathBuf::from),
        psk: cli_psk_inputs(cli),
    })
}

fn cli_psk_inputs(cli: &Cli) -> Option<CliPskInputs> {
    let identity = cli.psk_identity.as_ref()?;
    let key = cli.psk_key.as_ref()?;
    Some(CliPskInputs {
        identity: identity.clone(),
        // agentd accepts the PSK as raw bytes on the command line.
        key: PskKeyMaterial::Raw(key.expose_secret().as_bytes().to_vec()),
        exchange: match cli.psk_key_exchange {
            Some(PskKeyExchange::PskOnly) => PskKeyExchangeMode::PskOnly,
            Some(PskKeyExchange::PskDhe) | None => PskKeyExchangeMode::PskDhe,
        },
        groups: cli.psk_key_exchange_groups.clone(),
    })
}

pub(crate) fn parse(cli: Cli) -> anyhow::Result<SelectedProfile> {
    SelectedProfile::from_cli(cli, |cli| {
        Ok(vec![Box::new(DatastoreSourceComponent::from_file_datastore(
            "Inline server source",
            Arc::new(CliFileDatastore::new(cli_datastore_input_from_cli(cli))),
            local_services::input(cli)?,
        ))])
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{Cli, cli_datastore_input_from_cli};
    use crate::cli::HostIntegrationMode;
    use tacacsrs_config::PskDheKeSupportedGroup;
    use tacacsrs_config::crypto_types::PrivateKeyFormat;
    use tacacsrs_config::ValidationOptions;
    use tacacsrs_config::tacacsrs::LocalServices;
    use tacacsrs_config::input::{tacacs_plus_from_cli_input, tacacs_plus_from_file};

    fn sample_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("lde/containers/config/certificates")
            .join(file_name)
    }

    fn write_temp_config(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("agentd-config-test-{unique}.json"));
        fs::write(&path, contents).expect("temporary configuration file must be written");
        path
    }

    #[test]
    fn equivalent_cli_sonic_and_yang_inputs_preserve_canonical_values() {
        use std::collections::BTreeMap;

        use tacacsrs_config::input::{
            CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs, CliServerInput,
        };
        use tacacsrs_sonic::{SonicTacacsTables, map_sonic_tables_to_tacacs_plus};

        let ordered = [("192.0.2.21", 8), ("192.0.2.20", 1)];
        let servers = ordered
            .iter()
            .map(|(address, _)| {
                CliServerInput::new(format!("sonic-server-{address}"), format!("{address}:49"))
                    .with_timeout_seconds(7)
                    .with_single_connection(false)
            })
            .collect();
        let cli = tacacs_plus_from_cli_input(&CliDatastoreInput::new(
            CliConfigSource::Inline {
                servers,
                security: CliSecurity::from_cli_inputs(CliSecurityInputs {
                    shared_secret: Some("test-shared-secret".to_owned()),
                    ..Default::default()
                }),
            },
            "cli",
        ))
        .unwrap();
        let rows = ordered
            .iter()
            .map(|(address, priority)| {
                (
                    (*address).to_string(),
                    BTreeMap::from([
                        ("priority".to_owned(), priority.to_string()),
                        ("tcp_port".to_owned(), "49".to_owned()),
                        ("timeout".to_owned(), "7".to_owned()),
                        ("single_connection".to_owned(), "false".to_owned()),
                        ("passkey".to_owned(), "test-shared-secret".to_owned()),
                    ]),
                )
            })
            .collect();
        let sonic = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(BTreeMap::new(), rows))
            .unwrap();
        let yang = serde_json::json!({
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": ordered.iter().map(|(address, _)| serde_json::json!({
                    "name": format!("sonic-server-{address}"),
                    "server-type": "authentication authorization accounting",
                    "address": address,
                    "port": 49,
                    "timeout": 7,
                    "single-connection": false,
                    "shared-secret": "test-shared-secret",
                })).collect::<Vec<_>>()
            }
        });
        let parsed = tacacsrs_config::parse_yang_json(&yang.to_string()).unwrap();
        assert_eq!(cli, parsed);
        assert_eq!(sonic, parsed);
        assert_eq!(sonic.server[0].address, "192.0.2.21");
        for source in [&cli, &sonic, &parsed] {
            tacacsrs_config::prepare::validate_materialized_servers(
                source.server.iter(),
                &ValidationOptions::default(),
            )
            .unwrap();
            let endpoints = source
                .server
                .iter()
                .map(|server| {
                    tacacsrs_config::prepare::prepare_endpoint(
                        server,
                        tacacsrs_config::prepare::PrepareOptions::default(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(
                endpoints
                    .iter()
                    .map(|endpoint| endpoint.address().to_string())
                    .collect::<Vec<_>>(),
                ["192.0.2.21:49", "192.0.2.20:49"]
            );
            assert!(endpoints
                .iter()
                .all(|endpoint| !endpoint.single_connection()));
            assert_eq!(source, &parsed);
        }
    }

    #[test]
    fn tacacs_plus_from_config_loads_all_servers() {
        let path = write_temp_config(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "primary",
                            "server-type": "accounting",
                            "address": "192.0.2.20",
                            "port": 49,
                            "shared-secret": "secret1"
                        },
                        {
                            "name": "secondary",
                            "server-type": "accounting",
                            "address": "192.0.2.21",
                            "port": 49,
                            "shared-secret": "secret2"
                        }
                    ]
                }
            }"#,
        );

        let root = tacacs_plus_from_file(&path, &ValidationOptions::default())
            .expect("configuration file must load");
        fs::remove_file(&path).ok();

        assert_eq!(root.server.len(), 2);
        assert_eq!(root.server[0].name, "primary");
        assert_eq!(root.server[1].name, "secondary");
        assert_eq!(
            root.server[0]
                .shared_secret
                .as_ref()
                .map(tacacsrs_secrets::SecretString::expose_secret),
            Some("secret1"),
        );
    }

    #[test]
    fn tacacs_plus_from_cli_accepts_plain_text_shared_secret() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--shared-secret",
            "secret1",
        ]);

        let root = tacacs_plus_from_cli_input(&cli_datastore_input_from_cli(&cli))
            .expect("plain-text shared secret must load");
        assert_eq!(
            root.server[0]
                .shared_secret
                .as_ref()
                .map(tacacsrs_secrets::SecretString::expose_secret),
            Some("secret1"),
        );
    }

    #[test]
    fn cli_shared_secret_and_psk_debug_is_redacted() {
        let shared = "agentd-cli-shared-secret-sentinel";
        let psk = "agentd-cli-psk-sentinel";
        for args in [
            vec!["--shared-secret", shared],
            vec!["-k", shared],
            vec!["--use-tls", "--psk-identity", "client", "--psk-key", psk],
        ] {
            let cli = Cli::parse_from(
                ["tacacsrs-agentd", "--server-addr", "192.0.2.20:49"]
                    .into_iter()
                    .chain(args),
            );
            for output in [
                format!("{cli:?}"),
                format!("{cli:#?}"),
                format!("{:?}", Some(&cli)),
                format!("{:#?}", vec![&cli]),
            ] {
                assert!(
                    !output.contains(shared) && !output.contains(psk),
                    "Debug exposed an agentd CLI secret"
                );
            }
        }
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            psk,
        ]);
        let Some(super::CliPskInputs {
            key: super::PskKeyMaterial::Raw(key),
            ..
        }) = super::cli_psk_inputs(&cli)
        else {
            panic!("agentd must pass the PSK as raw bytes");
        };
        assert!(key == psk.as_bytes());
    }

    #[test]
    fn tacacs_plus_from_cli_enables_single_connection_negotiation() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--shared-secret",
            "secret1",
        ]);

        let root = tacacs_plus_from_cli_input(&cli_datastore_input_from_cli(&cli))
            .expect("CLI configuration must load");
        assert!(root.server[0].single_connection);
    }

    #[test]
    fn tacacs_plus_from_cli_dedicated_disables_single_connection_negotiation() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--shared-secret",
            "secret1",
            "--dedicated",
        ]);

        let root = tacacs_plus_from_cli_input(&cli_datastore_input_from_cli(&cli))
            .expect("CLI configuration must load");
        assert!(!root.server[0].single_connection);
    }

    #[test]
    fn service_mode_defaults_to_client_api_without_proxy_endpoint() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--shared-secret",
            "secret1",
        ]);

        let services = crate::local_services::patch(&cli).unwrap().apply(LocalServices::default()).unwrap();
        assert!(services.client_api_enabled);
        assert!(!services.tacacs_proxy_enabled);
        assert_eq!(cli.host_integration, HostIntegrationMode::Auto);
    }

    #[test]
    fn host_integration_accepts_explicit_none_and_systemd() {
        for (value, expected) in [
            ("none", HostIntegrationMode::None),
            ("systemd", HostIntegrationMode::Systemd),
        ] {
            let cli = Cli::parse_from([
                "tacacsrs-agentd",
                "--server-addr",
                "192.0.2.20:49",
                "--shared-secret",
                "secret1",
                "--host-integration",
                value,
            ]);
            assert_eq!(cli.host_integration, expected);
        }
    }

    #[test]
    fn service_mode_defaults_to_both_with_proxy_endpoint() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--shared-secret",
            "secret1",
            "--proxy-endpoint",
            "127.0.0.1:9050",
        ]);

        let services = crate::local_services::patch(&cli).unwrap().apply(LocalServices::default()).unwrap();
        assert!(services.client_api_enabled);
        assert!(services.tacacs_proxy_enabled);
    }

    #[test]
    fn service_mode_accepts_proxy_only() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--shared-secret",
            "secret1",
            "--service-mode",
            "tacacs-proxy",
            "--proxy-endpoint",
            "127.0.0.1:9050",
        ]);

        let services = crate::local_services::patch(&cli).unwrap().apply(LocalServices::default()).unwrap();
        assert!(!services.client_api_enabled);
        assert!(services.tacacs_proxy_enabled);
    }

    #[test]
    fn proxy_shared_secret_requires_proxy_endpoint() {
        let result = Cli::try_parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--proxy-shared-secret",
            "proxy-secret",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn proxy_shared_secret_conflicts_with_sonic_config_source() {
        let result = Cli::try_parse_from([
            "tacacsrs-agentd",
            "--sonic",
            "--proxy-endpoint",
            "127.0.0.1:9050",
            "--proxy-shared-secret",
            "proxy-secret",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn tacacs_plus_from_cli_accepts_pem_client_identity_files() {
        let cert_path = sample_path("client.crt");
        let key_path = sample_path("client.key");
        let expected_cert_der =
            fs::read(sample_path("client.crt.der")).expect("sample DER cert exists");
        let expected_key_der =
            fs::read(sample_path("client.key.der")).expect("sample DER key exists");

        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--use-tls",
            "--client-certificate",
            cert_path.to_str().expect("path must be UTF-8"),
            "--client-key",
            key_path.to_str().expect("path must be UTF-8"),
        ]);

        let root = tacacs_plus_from_cli_input(&cli_datastore_input_from_cli(&cli))
            .expect("PEM client identity must load");
        let inline = root.server[0]
            .client_identity
            .as_ref()
            .and_then(|identity| identity.certificate.as_ref())
            .and_then(|certificate| certificate.inline_definition.as_ref())
            .expect("inline certificate definition must be present");

        assert_eq!(inline.cert_data.as_deref(), Some(expected_cert_der.as_slice()));
        assert_eq!(
            inline
                .cleartext_private_key
                .as_ref()
                .map(tacacsrs_secrets::SecretBytes::expose_secret),
            Some(expected_key_der.as_slice()),
        );
        assert_eq!(inline.private_key_format, Some(PrivateKeyFormat::OneAsymmetricKeyFormat));
    }

    fn tls13_epsk_groups(cli: &Cli) -> Vec<PskDheKeSupportedGroup> {
        let mut root = tacacs_plus_from_cli_input(&cli_datastore_input_from_cli(cli))
            .expect("PSK configuration must build");
        root.server
            .remove(0)
            .client_identity
            .expect("client identity")
            .tls13_epsk
            .expect("tls13 epsk")
            .psk_dhe_ke_groups
    }

    #[test]
    fn tacacs_plus_from_cli_defaults_psk_to_dhe_groups() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            "secret",
        ]);

        let groups = tls13_epsk_groups(&cli);

        assert!(matches!(groups.first(), Some(PskDheKeSupportedGroup::Secp384r1)));
        assert!(matches!(groups.get(1), Some(PskDheKeSupportedGroup::Secp256r1)));
    }

    #[test]
    fn tacacs_plus_from_cli_allows_psk_only_mode() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            "secret",
            "--psk-key-exchange",
            "psk-only",
        ]);

        assert!(tls13_epsk_groups(&cli).is_empty());
    }

    #[test]
    fn tacacs_plus_from_cli_uses_custom_psk_dhe_groups() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            "secret",
            "--psk-key-exchange-groups",
            "secp256r1,x25519",
        ]);

        let groups = tls13_epsk_groups(&cli);

        assert!(matches!(groups.first(), Some(PskDheKeSupportedGroup::Secp256r1)));
        assert!(matches!(groups.get(1), Some(PskDheKeSupportedGroup::X25519)));
    }

    #[test]
    fn tacacs_plus_from_cli_rejects_psk_only_with_groups() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            "secret",
            "--psk-key-exchange",
            "psk-only",
            "--psk-key-exchange-groups",
            "secp384r1",
        ]);

        let error = tacacs_plus_from_cli_input(&cli_datastore_input_from_cli(&cli))
            .expect_err("PSK-only plus groups must fail");
        assert!(error.to_string().contains("--psk-key-exchange psk-only"));
        assert!(error.to_string().contains("--psk-key-exchange-groups"));
    }
}
