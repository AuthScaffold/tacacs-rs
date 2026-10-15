//! Startup composition for the daemon.
//!
//! [`prepare_service`] turns parsed CLI arguments into a
//! [`PreparedService`]. It selects the
//! datastore, resolves the local service listeners, loads the optional runtime
//! policy, builds credential providers, and constructs the waiting client
//! service. The host then supervises the result.
//!
//! The helpers map CLI inputs into canonical configuration inputs. They do not
//! route requests or materialize credentials.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use tacacsrs_agent::{
    EnabledServices, RuntimeHealthPublisher, RuntimePolicy, ServiceConfig, TacacsClientService,
};
use tacacsrs_config::input::{
    CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs, CliServerInput,
};
use tacacsrs_config::source::CliFileDatastore;
use tacacsrs_config::input::{CliPskInputs, PskKeyExchangeMode, PskKeyMaterial};
use tacacsrs_config::source::ConfigDatastore;
use tacacsrs_config::source::policy::{PolicyChange, PolicyFile, PolicyObservation};
use tacacsrs_sonic::{SonicConfigDb, SonicConnection};

use crate::cli::{Cli, PskKeyExchange, ServiceMode};
use crate::config_filter::config_filter_from_local_services;
use crate::credential_provider;
use crate::host_integration::HostIntegration;
use crate::local_services;
use crate::statistics;
use crate::supervision::PreparedService;

pub(crate) fn sonic_connection_from_cli(cli: &Cli) -> SonicConnection {
    let mut settings = SonicConnection::default();
    if let Some(url) = cli.sonic_redis_url.clone() {
        settings.url = url;
    }
    if let Some(db) = cli.sonic_redis_db {
        settings.db_index = db;
    }
    settings
}

async fn wait_for_sonic_forwarder(
    settings: &SonicConnection,
) -> anyhow::Result<tacacsrs_sonic::SonicForwarderSettings> {
    let mut delay = Duration::from_millis(250);
    loop {
        let load = settings.load_forwarder_settings().await;
        if let Ok(forwarder) = load {
            return Ok(forwarder);
        }
        log::warn!(
            "SONiC forwarder configuration is unavailable. The daemon retries before it binds."
        );
        tokio::time::sleep(delay).await;
        delay = delay.saturating_mul(2).min(Duration::from_secs(30));
    }
}

async fn sonic_forwarder_from_cli(
    cli: &Cli,
) -> anyhow::Result<Option<tacacsrs_sonic::SonicForwarderSettings>> {
    if !cli.sonic {
        return Ok(None);
    }
    if cli
        .service_mode
        .is_some_and(|mode| mode != ServiceMode::Both)
    {
        anyhow::bail!("SONiC central-agent mode requires --service-mode both");
    }
    Ok(Some(wait_for_sonic_forwarder(&sonic_connection_from_cli(cli)).await?))
}

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
        shared_secret: cli.shared_secret.clone(),
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
        key: PskKeyMaterial::Raw(key.as_bytes().to_vec()),
        exchange: match cli.psk_key_exchange {
            Some(PskKeyExchange::PskOnly) => PskKeyExchangeMode::PskOnly,
            Some(PskKeyExchange::PskDhe) | None => PskKeyExchangeMode::PskDhe,
        },
        groups: cli.psk_key_exchange_groups.clone(),
    })
}

/// Constructs the [`ConfigDatastore`] selected by the operator on the CLI.
///
/// This function wraps file and CLI flag inputs in a file-backed CLI datastore.
/// As a result, YANG configuration and CLI-provided TLS certificate and key
/// files can trigger hot reloads.
/// `--sonic` selects the SONiC ConfigDB-backed datastore.
///
/// Construction cannot fail. Each datastore validates its configuration lazily
/// in [`ConfigDatastore::load`]. As a result, configuration errors surface
/// during the daemon's initial load, not during construction.
fn build_datastore(
    cli: &Cli,
    sonic_forwarder: Option<tacacsrs_sonic::SonicForwarderSettings>,
) -> Arc<dyn ConfigDatastore> {
    if cli.sonic {
        let settings = sonic_connection_from_cli(cli);
        log::info!("SONiC ConfigDB datastore uses database index {}", settings.db_index);
        return Arc::new(match sonic_forwarder {
            Some(forwarder) => SonicConfigDb::with_bound_forwarder(settings, forwarder),
            None => SonicConfigDb::new(settings),
        });
    }

    if let Some(ref config_path) = cli.config {
        log::info!("Loading the YANG JSON configuration file at {}", config_path.display());
        return Arc::new(CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::YangFile {
                path: config_path.clone(),
            },
            "file",
        )));
    }

    Arc::new(CliFileDatastore::new(cli_datastore_input_from_cli(cli)))
}

/// Builds a [`PreparedService`] from parsed CLI arguments.
///
/// # Errors
/// Returns an error if the datastore, listeners, runtime policy, credential
/// providers, or client service cannot be prepared.
pub(crate) async fn prepare_service(cli: Cli) -> anyhow::Result<PreparedService> {
    let statistics_file = match &cli.statistics_file {
        Some(path) => {
            let mut protected = Vec::new();
            protected.extend(
                cli.config
                    .iter()
                    .chain(cli.runtime_policy.iter())
                    .chain(cli.local_services.iter())
                    .map(PathBuf::as_path),
            );
            protected.extend(
                cli.client_certificate
                    .iter()
                    .chain(cli.client_key.iter())
                    .map(std::path::Path::new),
            );
            protected.extend(
                cli.http_crl_certificate
                    .chunks_exact(2)
                    .map(|values| std::path::Path::new(&values[1])),
            );
            protected.extend(
                cli.http_ocsp_source
                    .chunks_exact(4)
                    .flat_map(|values| [&values[2], &values[3]])
                    .map(std::path::Path::new),
            );
            protected.extend(
                cli.http_ocsp_certificate
                    .chunks_exact(3)
                    .flat_map(|values| [&values[1], &values[2]])
                    .map(std::path::Path::new),
            );
            Some(statistics::StatisticsFile::new(path, &protected).await?)
        }
        None => None,
    };
    let credential_provider = credential_provider::build(&cli).await?;
    let host_integration = HostIntegration::from_environment(cli.host_integration)?;
    let sonic_forwarder = sonic_forwarder_from_cli(&cli).await?;
    let local_services = local_services::load(&cli, sonic_forwarder).await?;
    let prepared = tacacsrs_config::local_services::prepare_local_services(&local_services)?;
    if let Some(statistics) = &statistics_file {
        if let Some(path) = prepared.client_api() {
            statistics.protect_listener(path).await?;
        }
        if let Some(tacacsrs_config::local_services::ListenerEndpoint::Unix(path)) =
            prepared.tacacs_proxy()
        {
            statistics.protect_listener(path).await?;
        }
    }
    let enabled_services =
        EnabledServices::new(prepared.client_api().is_some(), prepared.tacacs_proxy().is_some());
    log::info!("Local service listeners: {prepared:?}");
    let config_filter = config_filter_from_local_services(&local_services)?;

    let datastore = build_datastore(&cli, sonic_forwarder);
    let (runtime_policy, policy_observation) = match &cli.runtime_policy {
        Some(path) => {
            let source = PolicyFile::new(path)?;
            let mut observation = source.observe().await?;
            let Some(PolicyChange::Changed(policy)) = observation.next().await? else {
                anyhow::bail!("Initial runtime policy was rejected");
            };
            let policy = RuntimePolicy::try_from(policy.as_ref())?;
            log::info!("Loaded runtime policy from {}", source.path().display());
            (policy, Some(observation))
        }
        None => (RuntimePolicy::default(), None),
    };
    let health = RuntimeHealthPublisher::new(enabled_services);
    let empty_tacacs_plus = tacacsrs_config::TacacsPlus::empty();
    let service = Arc::new(
        TacacsClientService::waiting_for_configuration(
            ServiceConfig {
                local_services,
                tacacs_plus: empty_tacacs_plus,
                validation_options: datastore.validation_options(),
                runtime_policy,
                disable_certificate_verification: cli.insecure_disable_certificate_verification,
            },
            health.clone(),
        )
        .context("Failed to build TACACS+ client service configuration")?,
    );
    Ok(PreparedService {
        datastore,
        service,
        health,
        config_filter,
        credential_provider,
        host_integration,
        policy_observation,
        statistics_file,
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
                    .map(tacacsrs_networking::PreparedEndpoint::address)
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

        let services = crate::local_services::from_cli(&cli, None).unwrap();
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

        let services = crate::local_services::from_cli(&cli, None).unwrap();
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

        let services = crate::local_services::from_cli(&cli, None).unwrap();
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
