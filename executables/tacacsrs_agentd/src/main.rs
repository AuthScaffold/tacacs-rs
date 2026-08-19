#![allow(clippy::doc_markdown)]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-agentd supports Linux GNU only");

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tacacsrs_agent::{
    EnabledServices, ProxyDownstreamObfuscation, RuntimeHealthPublisher, RuntimeLifecycle,
    RuntimePolicy, ServiceConfig, TacacsClientService,
};
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_cli_datastore::{
    CliConfigSource, CliDatastoreInput, CliFileDatastore, CliSecurity, CliSecurityInputs,
    CliServerInput,
};
use tacacsrs_cli_datastore::{CliPskInputs, PskKeyExchangeMode, PskKeyMaterial};
use tacacsrs_datastore::{ConfigDatastore, InitialLoadPolicy};
use tacacsrs_credential_resolution::{CredentialChangeSource, CredentialResolver};
use tacacsrs_sonic::{
    SonicConfigDb, SonicConnection, SonicCredentialChangeSource, SonicCredentialPolicy,
    SonicCredentialResolver, SonicCredentialRoots,
};
use tokio_util::sync::CancellationToken;

mod cli;
mod config_filter;
mod config_supervisor;
mod host_integration;
mod materialization_coordinator;
mod policy_file;
mod policy_supervisor;

use crate::cli::{Cli, ServiceMode};
use crate::cli::PskKeyExchange;
use crate::config_filter::{TacacsPlusFilter, config_filter_from_runtime_options};
use crate::config_supervisor::ConfigSupervisor;
use crate::host_integration::HostIntegration;
use crate::policy_file::PolicyFile;
use crate::policy_supervisor::PolicySupervisor;

fn parse_socket_mode(mode: &str) -> anyhow::Result<u32> {
    u32::from_str_radix(mode, 8).with_context(|| format!("Invalid socket mode: {mode}"))
}

/// Initializes the logger based on verbosity level.
///
/// When built with the `console` feature, the daemon uses the tokio-console
/// tracing subscriber instead of `env_logger`. This subscriber gives real-time
/// async runtime profiling with the `tokio-console` tool.
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
    if cli.sonic {
        return EnabledServices::BOTH;
    }
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

fn sonic_connection_from_cli(cli: &Cli) -> SonicConnection {
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
        let load = tokio::select! {
            load = settings.load_forwarder_settings() => load,
            signal = bootstrap_shutdown_signal() => {
                signal?;
                anyhow::bail!("shutdown requested during SONiC forwarder bootstrap");
            }
        };
        if let Ok(forwarder) = load {
            return Ok(forwarder);
        }
        log::warn!(
            "SONiC forwarder configuration is unavailable. The daemon retries before it binds."
        );
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            signal = bootstrap_shutdown_signal() => {
                signal?;
                anyhow::bail!("shutdown requested during SONiC forwarder bootstrap");
            }
        }
        delay = delay.saturating_mul(2).min(Duration::from_secs(30));
    }
}

async fn bootstrap_shutdown_signal() -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).context("register SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("register Ctrl-C handler"),
        _ = terminate.recv() => Ok(()),
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

async fn run_supervised_service(
    datastore: Arc<dyn ConfigDatastore>,
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
    config_filter: Arc<dyn TacacsPlusFilter>,
    credential_provider: CredentialProvider,
    host_integration: HostIntegration,
    policy_file: Option<PolicyFile>,
) -> anyhow::Result<()> {
    let (credential_resolver, credential_change_source) = credential_provider;
    let datastore_policy = datastore.runtime_policy();
    let supervisor = match (credential_resolver, credential_change_source) {
        (Some(resolver), Some(change_source)) => ConfigSupervisor::new_with_credential_provider(
            Arc::clone(&datastore),
            Arc::clone(&service),
            health.clone(),
            Arc::clone(&config_filter),
            resolver,
            change_source,
        ),
        (Some(resolver), None) => ConfigSupervisor::new_with_credential_resolver(
            Arc::clone(&datastore),
            Arc::clone(&service),
            health.clone(),
            Arc::clone(&config_filter),
            resolver,
        ),
        (None, _) => ConfigSupervisor::new(
            Arc::clone(&datastore),
            Arc::clone(&service),
            health.clone(),
            Arc::clone(&config_filter),
        ),
    };
    let cancellation = CancellationToken::new();
    let policy_supervisor = policy_file
        .map(|source| PolicySupervisor::new(source, Arc::clone(&service), health.clone()));

    if datastore_policy.initial_load == InitialLoadPolicy::FailFast {
        supervisor.load_initial(&cancellation).await?;
    }

    let host_task = {
        let cancellation = cancellation.clone();
        tokio::spawn(host_integration.run(health.subscribe(), cancellation))
    };

    let supervisor_task = {
        let cancellation = cancellation.clone();
        tokio::spawn(async move {
            let config_cancellation = cancellation.clone();
            let config_future = async move {
                if datastore_policy.initial_load == InitialLoadPolicy::RetryUntilAvailable {
                    supervisor.run(&config_cancellation).await
                } else {
                    supervisor.run_notifications(&config_cancellation).await;
                    Ok(())
                }
            };

            let Some(policy_supervisor) = policy_supervisor else {
                return config_future.await;
            };
            let policy_cancellation = cancellation.clone();
            tokio::select! {
                result = config_future => result,
                result = policy_supervisor.run(&policy_cancellation) => {
                    if policy_cancellation.is_cancelled() {
                        result
                    } else {
                        result?;
                        Err(anyhow::anyhow!("Runtime policy supervisor stopped unexpectedly"))
                    }
                }
            }
        })
    };

    supervise_tasks(service.serve(), host_task, supervisor_task, cancellation, health).await
}

/// Coordinates the service, host integration, and configuration supervisor as
/// peers so that an unexpected exit of any one of them is observed immediately.
///
/// The configuration supervisor is critical. If it returns, errors, or panics
/// while the service still serves requests, the runtime keeps serving stale
/// configuration. This is fatal.
async fn supervise_tasks(
    service_future: impl std::future::Future<Output = anyhow::Result<()>>,
    mut host_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    mut supervisor_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    cancellation: CancellationToken,
    health: RuntimeHealthPublisher,
) -> anyhow::Result<()> {
    let service_future = std::pin::pin!(service_future);

    let mut host_task_completed = false;
    let mut supervisor_task_completed = false;
    let service_result = tokio::select! {
        result = service_future => result,
        result = &mut host_task => {
            host_task_completed = true;
            match result.context("Host integration task failed")? {
                Ok(()) => Err(anyhow::anyhow!("Host integration stopped unexpectedly")),
                Err(error) => Err(error.context("Host integration failed")),
            }
        }
        result = &mut supervisor_task => {
            supervisor_task_completed = true;
            // Publish a typed failure without embedding the underlying configuration or credential error.
            health.set_lifecycle(RuntimeLifecycle::Failed);
            Err(supervisor_exit_to_fatal_error(result))
        }
    };

    cancellation.cancel();
    if !supervisor_task_completed {
        supervisor_task
            .await
            .context("Configuration supervisor task failed")??;
    }
    if !host_task_completed {
        host_task.await.context("Host integration task failed")??;
    }

    service_result
}

/// Classifies an unexpected configuration-supervisor task outcome as a fatal error.
fn supervisor_exit_to_fatal_error(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow::anyhow!("Configuration supervisor stopped unexpectedly"),
        Ok(Err(error)) => error.context("Configuration supervisor failed"),
        Err(join_error) => {
            anyhow::Error::new(join_error).context("Configuration supervisor task panicked")
        }
    }
}

type CredentialProvider =
    (Option<Arc<dyn CredentialResolver>>, Option<Arc<dyn CredentialChangeSource>>);

fn build_credential_provider(cli: &Cli) -> CredentialProvider {
    if !cli.sonic {
        return (None, None);
    }
    let resolver = Arc::new(SonicCredentialResolver::reloadable(
        SonicCredentialRoots::default(),
        SonicCredentialPolicy::production_from_root_group(),
    )) as Arc<dyn CredentialResolver>;
    let settings = sonic_connection_from_cli(cli);
    let change_source = settings.credential_watch_root.map(|root| {
        Arc::new(SonicCredentialChangeSource::new(root, settings.debounce))
            as Arc<dyn CredentialChangeSource>
    });
    (Some(resolver), change_source)
}

/// Starts the central TACACS+ client service process.
///
/// The service listens on the configured local IPC endpoint. It maintains
/// persistent upstream TACACS+ connections with ordered failover. It stops in
/// an orderly manner when it receives a termination signal.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);
    let host_integration = HostIntegration::from_environment(cli.host_integration)?;
    let sonic_forwarder = sonic_forwarder_from_cli(&cli).await?;
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

    if enabled_services.client_api() && matches!(endpoint, IpcEndpoint::Tcp(_)) {
        anyhow::bail!("Linux deployments must use a Unix domain socket endpoint");
    }

    let configured_proxy_endpoint = cli
        .proxy_endpoint
        .as_deref()
        .map(IpcEndpoint::from_str)
        .transpose()?;
    let proxy_endpoint = match sonic_forwarder {
        Some(forwarder) => {
            let endpoint = IpcEndpoint::Tcp(forwarder.socket_address());
            if configured_proxy_endpoint
                .as_ref()
                .is_some_and(|configured| configured != &endpoint)
            {
                anyhow::bail!("CLI proxy endpoint conflicts with TACPLUS_FORWARDER|global");
            }
            Some(endpoint)
        }
        None => configured_proxy_endpoint,
    };

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

    let datastore = build_datastore(&cli, sonic_forwarder);
    let policy_file = cli.runtime_policy.clone().map(PolicyFile::new);
    let runtime_policy = match &policy_file {
        Some(source) => {
            let policy = source.load().await?;
            log::info!("Loaded runtime policy from {}", source.path().display());
            policy
        }
        None => RuntimePolicy::default(),
    };
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
                runtime_policy,
                socket_mode: parse_socket_mode(&cli.socket_mode)?,
                disable_certificate_verification: cli.insecure_disable_certificate_verification,
            },
            health.clone(),
        )
        .context("Failed to build TACACS+ client service configuration")?,
    );
    let credential_provider = build_credential_provider(&cli);
    run_supervised_service(
        datastore,
        service,
        health,
        config_filter,
        credential_provider,
        host_integration,
        policy_file,
    )
    .await
}

#[cfg(test)]
mod supervision_tests {
    use std::future;

    use tacacsrs_agent::{EnabledServices, RuntimeHealthPublisher, RuntimeLifecycle};
    use tokio_util::sync::CancellationToken;

    use super::{supervise_tasks, supervisor_exit_to_fatal_error};

    fn health() -> RuntimeHealthPublisher {
        RuntimeHealthPublisher::new(EnabledServices::CLIENT_API)
    }

    fn wait_for_cancel(
        cancellation: CancellationToken,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            cancellation.cancelled().await;
            Ok(())
        })
    }

    #[tokio::test]
    async fn supervisor_early_return_is_fatal_and_marks_failed() {
        let health = health();
        let cancellation = CancellationToken::new();
        let host_task = wait_for_cancel(cancellation.clone());
        let supervisor_task = tokio::spawn(async { Ok(()) });

        let result = supervise_tasks(
            future::pending::<anyhow::Result<()>>(),
            host_task,
            supervisor_task,
            cancellation,
            health.clone(),
        )
        .await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("stopped unexpectedly"));
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test]
    async fn supervisor_error_is_fatal_and_marks_failed() {
        let health = health();
        let cancellation = CancellationToken::new();
        let host_task = wait_for_cancel(cancellation.clone());
        let supervisor_task =
            tokio::spawn(async { Err(anyhow::anyhow!("supervisor failure detail")) });

        let result = supervise_tasks(
            future::pending::<anyhow::Result<()>>(),
            host_task,
            supervisor_task,
            cancellation,
            health.clone(),
        )
        .await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Configuration supervisor failed"));
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test]
    async fn supervisor_panic_is_fatal_and_marks_failed() {
        let health = health();
        let cancellation = CancellationToken::new();
        let host_task = wait_for_cancel(cancellation.clone());
        let supervisor_task = tokio::spawn(async {
            panic!("supervisor panic");
        });

        let result = supervise_tasks(
            future::pending::<anyhow::Result<()>>(),
            host_task,
            supervisor_task,
            cancellation,
            health.clone(),
        )
        .await;

        assert!(result.unwrap_err().to_string().contains("panicked"));
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test]
    async fn normal_service_exit_joins_without_false_failure() {
        let health = health();
        let cancellation = CancellationToken::new();
        let host_task = wait_for_cancel(cancellation.clone());
        let supervisor_task = wait_for_cancel(cancellation.clone());

        let result = supervise_tasks(
            future::ready(Ok(())),
            host_task,
            supervisor_task,
            cancellation,
            health.clone(),
        )
        .await;

        assert!(result.is_ok());
        assert_ne!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test]
    async fn listener_error_propagates_without_marking_failed() {
        let health = health();
        let cancellation = CancellationToken::new();
        let host_task = wait_for_cancel(cancellation.clone());
        let supervisor_task = wait_for_cancel(cancellation.clone());

        let result = supervise_tasks(
            future::ready(Err(anyhow::anyhow!("listener bind failed"))),
            host_task,
            supervisor_task,
            cancellation,
            health.clone(),
        )
        .await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("listener bind failed"));
        assert_ne!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test]
    async fn host_integration_error_propagates() {
        let health = health();
        let cancellation = CancellationToken::new();
        let host_task = tokio::spawn(async { Err(anyhow::anyhow!("host integration failure")) });
        let supervisor_task = wait_for_cancel(cancellation.clone());

        let result = supervise_tasks(
            future::pending::<anyhow::Result<()>>(),
            host_task,
            supervisor_task,
            cancellation,
            health.clone(),
        )
        .await;

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Host integration failed"));
    }

    #[test]
    fn fatal_error_classification_distinguishes_clean_and_errored_exits() {
        let stopped = supervisor_exit_to_fatal_error(Ok(Ok(())));
        assert!(stopped.to_string().contains("stopped unexpectedly"));

        let failed = supervisor_exit_to_fatal_error(Ok(Err(anyhow::anyhow!("detail"))));
        assert!(failed
            .to_string()
            .contains("Configuration supervisor failed"));
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{Cli, cli_datastore_input_from_cli, enabled_services_from_cli};
    use crate::cli::HostIntegrationMode;
    use tacacsrs_agent::EnabledServices;
    use tacacsrs_config::PskDheKeSupportedGroup;
    use tacacsrs_config::crypto_types::PrivateKeyFormat;
    use tacacsrs_config::ValidationOptions;
    use tacacsrs_cli_datastore::{tacacs_plus_from_cli_input, tacacs_plus_from_file};

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

        assert_eq!(enabled_services_from_cli(&cli), EnabledServices::CLIENT_API);
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
    fn sonic_mode_always_enables_client_api_and_proxy() {
        let cli = Cli::parse_from(["tacacsrs-agentd", "--sonic"]);

        assert_eq!(enabled_services_from_cli(&cli), EnabledServices::BOTH);
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
