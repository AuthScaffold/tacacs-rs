#![allow(clippy::doc_markdown)]

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tacacsrs_agent::{
    EnabledServices, ProxyDownstreamObfuscation, RuntimeHealthPublisher, ServiceConfig,
    TacacsClientService,
};
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_cli_datastore::{
    CliConfigSource, CliDatastoreInput, CliFileDatastore, CliSecurity, CliSecurityInputs,
    CliServerInput,
};
use tacacsrs_cli_datastore::{CliPskInputs, PskKeyExchangeMode, PskKeyMaterial};
use tacacsrs_datastore::{ConfigDatastore, InitialLoadPolicy};
use tacacsrs_sonic::{SonicConfigDb, SonicConnection, DEFAULT_REDIS_URL};
use tokio_util::sync::CancellationToken;

mod cli;
mod config_filter;
mod config_supervisor;
mod systemd_notify;

use crate::cli::{Cli, ServiceMode};
use crate::cli::PskKeyExchange;
use crate::config_filter::{TacacsPlusFilter, config_filter_from_runtime_options};
use crate::config_supervisor::ConfigSupervisor;
use crate::systemd_notify::SystemdNotifier;

#[cfg(unix)]
fn parse_socket_mode(mode: &str) -> anyhow::Result<u32> {
    u32::from_str_radix(mode, 8).with_context(|| format!("Invalid socket mode: {mode}"))
}

/// Initializes the logger based on verbosity level.
///
/// When built with the `console` feature, the tokio-console tracing
/// subscriber is used instead of `env_logger`, enabling real-time async
/// runtime profiling via the `tokio-console` tool.
#[cfg(feature = "console")]
fn init_logger(_verbose: u8) {
    console_subscriber::init();
}

/// Initializes the logger based on verbosity level.
#[cfg(not(feature = "console"))]
fn init_logger(verbose: u8) {
    let level = match verbose {
        0 => return,
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    if env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .try_init()
        .is_ok()
    {
        log::debug!("Logging initialized at level: {level}");
    }
}

fn enabled_services_from_cli(cli: &Cli) -> EnabledServices {
    match cli.service_mode.unwrap_or_else(|| {
        if cli.proxy_endpoint.is_some() {
            ServiceMode::Both
        } else {
            ServiceMode::ClientApi
        }
    }) {
        ServiceMode::ClientApi => EnabledServices::CLIENT_API,
        ServiceMode::TacacsProxy => EnabledServices::TACACS_PROXY,
        ServiceMode::Both => EnabledServices::BOTH,
    }
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

/// Construct the [`ConfigDatastore`] selected by the operator on the CLI.
///
/// File and CLI flag inputs are wrapped in a file-backed CLI datastore so YANG
/// config and CLI-provided TLS certificate/key files can trigger hot reloads.
/// `--sonic` selects the SONiC ConfigDB-backed datastore.
///
/// Construction is infallible: every datastore validates its configuration
/// lazily in [`ConfigDatastore::load`], so configuration errors surface when
/// the daemon performs its initial load rather than here.
fn build_datastore(cli: &Cli) -> Arc<dyn ConfigDatastore> {
    if cli.sonic {
        let mut settings = SonicConnection::default();
        if let Some(url) = cli.sonic_redis_url.clone() {
            settings.url = url;
        } else {
            settings.url = DEFAULT_REDIS_URL.to_string();
        }
        if let Some(db) = cli.sonic_redis_db {
            settings.db_index = db;
        }
        log::info!(
            "Configured SONiC ConfigDB datastore: url='{}', db={}",
            settings.url,
            settings.db_index,
        );
        return Arc::new(SonicConfigDb::new(settings));
    }

    if let Some(ref config_path) = cli.config {
        log::info!("Loading YANG JSON configuration from {}", config_path.display());
        return Arc::new(CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::YangFile {
                path: config_path.clone(),
            },
            "file",
        )));
    }

    Arc::new(CliFileDatastore::new(cli_datastore_input_from_cli(cli)))
}

async fn run_supervised_service(
    datastore: Arc<dyn ConfigDatastore>,
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
    config_filter: Arc<dyn TacacsPlusFilter>,
) -> anyhow::Result<()> {
    let datastore_policy = datastore.runtime_policy();
    let supervisor = ConfigSupervisor::new(
        Arc::clone(&datastore),
        Arc::clone(&service),
        health.clone(),
        config_filter,
    );
    let cancellation = CancellationToken::new();

    if datastore_policy.initial_load == InitialLoadPolicy::FailFast {
        supervisor.load_initial(&cancellation).await?;
    }

    let status_notifier = Arc::new(SystemdNotifier::from_env());
    status_notifier.publish_server_state(service.server_count());
    let status_task = {
        let cancellation = cancellation.clone();
        let status_notifier = Arc::clone(&status_notifier);
        let mut health = health.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => return,
                    result = health.changed() => {
                        if result.is_err() {
                            return;
                        }
                        status_notifier.publish_server_state(
                            health.borrow().eligible_server_count(),
                        );
                    }
                }
            }
        })
    };

    let supervisor_task = {
        let cancellation = cancellation.clone();
        tokio::spawn(async move {
            if datastore_policy.initial_load == InitialLoadPolicy::RetryUntilAvailable {
                supervisor.run(&cancellation).await
            } else {
                supervisor.run_notifications(&cancellation).await;
                Ok(())
            }
        })
    };

    let service_result = service.serve().await;
    cancellation.cancel();
    supervisor_task
        .await
        .context("Configuration supervisor task failed")??;
    status_task.await.context("Systemd status task failed")?;

    service_result
}

/// Starts the central TACACS+ client service process.
///
/// The service listens on the configured local IPC endpoint, maintains
/// persistent upstream TACACS+ connections with ordered failover, and shuts
/// down gracefully when it receives a termination signal.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);
    let enabled_services = enabled_services_from_cli(&cli);

    let endpoint = cli
        .listen_endpoint
        .as_deref()
        .map(IpcEndpoint::from_str)
        .transpose()?
        .unwrap_or_else(IpcEndpoint::default_local);

    if enabled_services.client_api() {
        log::info!("Client API endpoint: {endpoint:?}");
    } else {
        log::info!("Client API service disabled");
    }

    #[cfg(unix)]
    if enabled_services.client_api() && matches!(endpoint, IpcEndpoint::Tcp(_)) {
        anyhow::bail!("Linux deployments must use a Unix domain socket endpoint");
    }

    let proxy_endpoint = cli
        .proxy_endpoint
        .as_deref()
        .map(IpcEndpoint::from_str)
        .transpose()?;

    if let Some(proxy_endpoint) = &proxy_endpoint {
        if enabled_services.client_api() && proxy_endpoint == &endpoint {
            anyhow::bail!("Proxy endpoint must be different from the IPC endpoint");
        }
    }

    if enabled_services.tacacs_proxy() {
        let Some(proxy_endpoint) = &proxy_endpoint else {
            anyhow::bail!("The TACACS+ proxy service requires --proxy-endpoint");
        };
        log::info!("TACACS+ proxy endpoint: {proxy_endpoint:?}");
    } else if proxy_endpoint.is_some() {
        anyhow::bail!(
            "--proxy-endpoint requires --service-mode tacacs-proxy or --service-mode both"
        );
    }
    let config_filter = config_filter_from_runtime_options(
        enabled_services,
        proxy_endpoint.as_ref(),
        cli.proxy_shared_secret.clone(),
    );

    let datastore = build_datastore(&cli);
    let health = RuntimeHealthPublisher::new(enabled_services);
    let empty_tacacs_plus = tacacsrs_config::TacacsPlus::empty();
    let service = Arc::new(
        TacacsClientService::waiting_for_configuration(
            ServiceConfig {
                enabled_services,
                endpoint,
                proxy_endpoint,
                proxy_downstream_obfuscation: ProxyDownstreamObfuscation::default(),
                tacacs_plus: empty_tacacs_plus,
                preferred_probe_interval: Duration::from_secs(cli.preferred_probe_interval_seconds),
                #[cfg(unix)]
                socket_mode: parse_socket_mode(&cli.socket_mode)?,
                disable_certificate_verification: cli.insecure_disable_certificate_verification,
            },
            health.clone(),
        )
        .context("Failed to build TACACS+ client service configuration")?,
    );
    run_supervised_service(datastore, service, health, config_filter).await
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{Cli, cli_datastore_input_from_cli, enabled_services_from_cli};
    use tacacsrs_agent::EnabledServices;
    use tacacsrs_config::PskDheKeSupportedGroup;
    use tacacsrs_config::crypto_types::PrivateKeyFormat;
    use tacacsrs_config::ValidationOptions;
    use tacacsrs_cli_datastore::{tacacs_plus_from_cli_input, tacacs_plus_from_file};

    fn sample_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("libraries")
            .join("tacacsrs_networking")
            .join("examples")
            .join("samples")
            .join(file_name)
    }

    fn write_temp_config(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("agentd-config-test-{unique}.json"));
        fs::write(&path, contents).expect("temp config should be written");
        path
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
            .expect("config file should load");
        fs::remove_file(&path).ok();

        assert_eq!(root.server.len(), 2);
        assert_eq!(root.server[0].name, "primary");
        assert_eq!(root.server[1].name, "secondary");
        assert_eq!(root.server[0].shared_secret.as_deref(), Some("secret1"));
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
            .expect("plain-text shared secret should load");
        assert_eq!(root.server[0].shared_secret.as_deref(), Some("secret1"));
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
            .expect("CLI config should load");
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
            .expect("CLI config should load");
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

        assert_eq!(enabled_services_from_cli(&cli), EnabledServices::CLIENT_API);
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

        assert_eq!(enabled_services_from_cli(&cli), EnabledServices::BOTH);
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

        assert_eq!(enabled_services_from_cli(&cli), EnabledServices::TACACS_PROXY);
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
            cert_path.to_str().expect("path should be UTF-8"),
            "--client-key",
            key_path.to_str().expect("path should be UTF-8"),
        ]);

        let root = tacacs_plus_from_cli_input(&cli_datastore_input_from_cli(&cli))
            .expect("PEM client identity should load");
        let inline = root.server[0]
            .client_identity
            .as_ref()
            .and_then(|identity| identity.certificate.as_ref())
            .and_then(|certificate| certificate.inline_definition.as_ref())
            .expect("inline certificate definition should be present");

        assert_eq!(inline.cert_data.as_deref(), Some(expected_cert_der.as_slice()));
        assert_eq!(inline.cleartext_private_key.as_deref(), Some(expected_key_der.as_slice()));
        assert_eq!(inline.private_key_format, Some(PrivateKeyFormat::OneAsymmetricKeyFormat));
    }

    fn tls13_epsk_groups(cli: &Cli) -> Vec<PskDheKeSupportedGroup> {
        let mut root = tacacs_plus_from_cli_input(&cli_datastore_input_from_cli(cli))
            .expect("PSK config should build");
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
            .expect_err("PSK-only plus groups should fail");
        assert!(error.to_string().contains("--psk-key-exchange psk-only"));
        assert!(error.to_string().contains("--psk-key-exchange-groups"));
    }
}
