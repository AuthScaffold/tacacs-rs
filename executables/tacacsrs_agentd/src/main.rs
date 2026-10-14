#![allow(clippy::doc_markdown)]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-agentd supports Linux GNU only");

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tacacsrs_agent::runtime::{ConfigSupervisor, PolicySupervisor, TacacsPlusFilter};
use tacacsrs_agent::{
    EnabledServices, RuntimeHealthPublisher, RuntimeLifecycle, RuntimePolicy, ServiceConfig,
    TacacsClientService,
};
use tacacsrs_config::input::{
    CliConfigSource, CliDatastoreInput, CliFileDatastore, CliSecurity, CliSecurityInputs,
    CliServerInput,
};
use tacacsrs_config::input::{CliPskInputs, PskKeyExchangeMode, PskKeyMaterial};
use tacacsrs_config::source::{ConfigDatastore, InitialLoadPolicy};
use tacacsrs_config::source::policy::{
    FilePolicyObservation, PolicyChange, PolicyFile, PolicyObservation,
};
use tacacsrs_sonic::{SonicConfigDb, SonicConnection};
use tokio_util::sync::CancellationToken;

mod cli;
mod config_filter;
mod credential_provider;
mod host_integration;
mod local_services;

use crate::cli::{Cli, ServiceMode};
use crate::cli::PskKeyExchange;
use crate::config_filter::config_filter_from_local_services;
use crate::credential_provider::CredentialProvider;
use crate::host_integration::HostIntegration;

/// Initializes the logger based on verbosity level.
///
/// With the `console` feature and `tokio_unstable`, the daemon uses the tokio-console
/// tracing subscriber instead of `env_logger`. This subscriber gives real-time
/// async runtime profiling with the `tokio-console` tool.
#[cfg(all(feature = "console", tokio_unstable))]
fn init_logger(_verbose: u8) {
    console_subscriber::init();
}

/// Initializes the logger based on verbosity level.
#[cfg(not(all(feature = "console", tokio_unstable)))]
fn init_logger(verbose: u8) {
    #[cfg(feature = "console")]
    eprintln!("Tokio Console profiling is disabled. Rebuild with RUSTFLAGS=\"--cfg tokio_unstable\" to enable it.");
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

struct PreparedService {
    datastore: Arc<dyn ConfigDatastore>,
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
    config_filter: Arc<dyn TacacsPlusFilter>,
    credential_provider: CredentialProvider,
    host_integration: HostIntegration,
    policy_observation: Option<FilePolicyObservation>,
}

impl PreparedService {
    async fn run(self, cancellation: CancellationToken) -> anyhow::Result<()> {
        let Self {
            datastore,
            service,
            health,
            config_filter,
            credential_provider,
            host_integration,
            policy_observation,
        } = self;
        let (credential_resolver, credential_change_source) = credential_provider;
        let datastore_policy = datastore.runtime_policy();
        let mut supervisor = ConfigSupervisor::new(
            Arc::clone(&datastore),
            Arc::clone(&service),
            health.clone(),
            config_filter,
        );
        if let Some(resolver) = credential_resolver {
            supervisor = supervisor.with_credential_resolver(resolver);
        }
        if let Some(change_source) = credential_change_source {
            supervisor = supervisor.with_credential_changes(change_source);
        }
        let policy_supervisor = policy_observation
            .map(|observation| PolicySupervisor::new(observation, Arc::clone(&service)));

        if datastore_policy.initial_load == InitialLoadPolicy::FailFast {
            supervisor
                .initialize_until(cancellation.cancelled())
                .await?;
        }
        if cancellation.is_cancelled() {
            return Ok(());
        }

        let host_task = {
            let cancellation = cancellation.clone();
            tokio::spawn(host_integration.run(health.subscribe(), cancellation))
        };

        let supervisor_task = {
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                let config_cancellation = cancellation.clone();
                let config_future = supervisor.run_until(config_cancellation.cancelled());

                let Some(policy_supervisor) = policy_supervisor else {
                    return config_future.await;
                };
                let policy_cancellation = cancellation.clone();
                tokio::select! {
                    result = config_future => result,
                    result = policy_supervisor.run_until(policy_cancellation.cancelled()) => {
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

        supervise_tasks(
            service.serve_until(cancellation.cancelled()),
            host_task,
            supervisor_task,
            cancellation.clone(),
            health,
            || service.shutdown_timeout(),
        )
        .await
    }
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
    shutdown_timeout: impl FnOnce() -> Duration,
) -> anyhow::Result<()> {
    let _tasks = PeerTasks {
        cancellation: cancellation.clone(),
        host: host_task.abort_handle(),
        supervisor: supervisor_task.abort_handle(),
    };
    let mut service_future = Box::pin(service_future);

    let mut service_completed = false;
    let mut peer_failed = false;
    let mut host_task_completed = false;
    let mut supervisor_task_completed = false;
    let mut service_result = tokio::select! {
        biased;
        () = cancellation.cancelled() => Ok(()),
        result = &mut service_future => { service_completed = true; result },
        result = &mut host_task => {
            host_task_completed = true;
            peer_failed = true;
            health.set_lifecycle(RuntimeLifecycle::Failed);
            match result {
                Ok(Ok(())) => Err(anyhow::anyhow!("Host integration stopped unexpectedly")),
                Ok(Err(error)) => Err(error.context("Host integration failed")),
                Err(error) => Err(anyhow::Error::new(error).context("Host integration task failed")),
            }
        }
        result = &mut supervisor_task => {
            supervisor_task_completed = true;
            peer_failed = true;
            // Publish a typed failure without embedding the underlying configuration or credential error.
            health.set_lifecycle(RuntimeLifecycle::Failed);
            Err(supervisor_exit_to_fatal_error(result))
        }
    };

    let deadline =
        if let Some(deadline) = tokio::time::Instant::now().checked_add(shutdown_timeout()) {
            deadline
        } else {
            if service_result.is_ok() {
                service_result = Err(anyhow::anyhow!("Shutdown budget exceeds the clock range"));
            }
            tokio::time::Instant::now()
        };
    cancellation.cancel();
    let cleanup = async {
        if !service_completed {
            let result = (&mut service_future).await;
            if service_result.is_ok() {
                service_result = result;
            }
        }
        if !supervisor_task_completed {
            let result = (&mut supervisor_task)
                .await
                .context("Configuration supervisor task failed")
                .and_then(std::convert::identity);
            supervisor_task_completed = true;
            peer_failed |= result.is_err();
            if service_result.is_ok() {
                service_result = result;
            }
        }
        if !host_task_completed {
            let result = (&mut host_task)
                .await
                .context("Host integration task failed")
                .and_then(std::convert::identity);
            host_task_completed = true;
            peer_failed |= result.is_err();
            if service_result.is_ok() {
                service_result = result;
            }
        }
    };
    if tokio::time::timeout_at(deadline, cleanup).await.is_err() {
        health.set_lifecycle(RuntimeLifecycle::Failed);
        drop(service_future);
        host_task.abort();
        supervisor_task.abort();
        if !host_task_completed {
            let _ = host_task.await;
        }
        if !supervisor_task_completed {
            let _ = supervisor_task.await;
        }
        return service_result.and(Err(anyhow::anyhow!("Shutdown deadline elapsed")));
    }

    if peer_failed {
        health.set_lifecycle(RuntimeLifecycle::Failed);
    }
    service_result
}

struct PeerTasks {
    cancellation: CancellationToken,
    host: tokio::task::AbortHandle,
    supervisor: tokio::task::AbortHandle,
}

impl Drop for PeerTasks {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.host.abort();
        self.supervisor.abort();
    }
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

/// Starts the central TACACS+ client service process.
///
/// The service listens on the configured local IPC endpoint. It maintains
/// persistent upstream TACACS+ connections with ordered failover. It stops in
/// an orderly manner when it receives a termination signal.
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cli.worker_threads.get())
        .enable_all()
        .build()
        .context("Failed to build the Tokio runtime")?;

    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    init_logger(cli.verbose);
    let signals = ProcessSignals::register()?;
    run_until(cli, signals.wait()).await
}

struct ProcessSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl ProcessSignals {
    fn register() -> anyhow::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("register SIGINT handler")?,
            terminate: signal(SignalKind::terminate()).context("register SIGTERM handler")?,
        })
    }

    async fn wait(mut self) -> anyhow::Result<()> {
        tokio::select! {
            signal = self.interrupt.recv() => { signal.context("SIGINT stream ended")?; }
            signal = self.terminate.recv() => { signal.context("SIGTERM stream ended")?; }
        }
        log::info!("Shutdown requested by the host");
        Ok(())
    }
}

async fn run_until(
    cli: Cli,
    stop: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let application = async {
        let prepared = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            prepared = prepare_service(cli) => prepared?,
        };
        prepared.run(cancellation.clone()).await
    };
    tokio::pin!(application);
    tokio::select! {
        biased;
        signal = stop => {
            cancellation.cancel();
            let drained = application.await;
            signal.and(drained)
        }
        result = &mut application => result,
    }
}

async fn prepare_service(cli: Cli) -> anyhow::Result<PreparedService> {
    let credential_provider = credential_provider::build(&cli)?;
    let host_integration = HostIntegration::from_environment(cli.host_integration)?;
    let sonic_forwarder = sonic_forwarder_from_cli(&cli).await?;
    let local_services = local_services::load(&cli, sonic_forwarder).await?;
    let prepared = tacacsrs_config::local_services::prepare_local_services(&local_services)?;
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
    })
}

#[cfg(test)]
mod supervision_tests {
    use std::future;

    use tacacsrs_agent::{EnabledServices, RuntimeHealthPublisher, RuntimeLifecycle};
    use tokio_util::sync::CancellationToken;

    use super::supervisor_exit_to_fatal_error;

    async fn supervise_tasks(
        service: impl std::future::Future<Output = anyhow::Result<()>>,
        host: tokio::task::JoinHandle<anyhow::Result<()>>,
        supervisor: tokio::task::JoinHandle<anyhow::Result<()>>,
        cancellation: CancellationToken,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        super::supervise_tasks(service, host, supervisor, cancellation, health, || {
            tacacsrs_agent::RuntimePolicy::default().shutdown_timeout()
        })
        .await
    }

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

    async fn service_until_cancel(cancellation: CancellationToken) -> anyhow::Result<()> {
        cancellation.cancelled().await;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_phases_share_one_captured_deadline() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let service = async move {
            child.cancelled().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(())
        };
        let host = tokio::spawn(future::pending::<anyhow::Result<()>>());
        let host_finished = host.abort_handle();
        let supervisor = tokio::spawn(future::pending::<anyhow::Result<()>>());
        let supervisor_finished = supervisor.abort_handle();
        let budget = Arc::new(AtomicU64::new(3));
        let updated = budget.clone();
        let child = cancellation.clone();
        let update = tokio::spawn(async move {
            child.cancelled().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            updated.store(100, Ordering::Release);
        });
        cancellation.cancel();
        let started = tokio::time::Instant::now();
        let health = health();
        let result =
            super::supervise_tasks(service, host, supervisor, cancellation, health.clone(), || {
                Duration::from_secs(budget.load(Ordering::Acquire))
            })
            .await;
        update.await.unwrap();
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Shutdown deadline elapsed"));
        assert_eq!(started.elapsed(), Duration::from_secs(3));
        assert!(host_finished.is_finished());
        assert!(supervisor_finished.is_finished());
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test(start_paused = true)]
    async fn primary_peer_error_survives_stalled_service_teardown() {
        use std::time::Duration;

        let cancellation = CancellationToken::new();
        let host = tokio::spawn(async { Err(anyhow::anyhow!("primary host failure")) });
        let supervisor = tokio::spawn(future::pending::<anyhow::Result<()>>());
        let supervisor_finished = supervisor.abort_handle();
        let started = tokio::time::Instant::now();
        let health = health();
        let result = super::supervise_tasks(
            future::pending(),
            host,
            supervisor,
            cancellation,
            health.clone(),
            || Duration::from_secs(2),
        )
        .await;
        assert!(format!("{:#}", result.unwrap_err()).contains("primary host failure"));
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert!(supervisor_finished.is_finished());
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test(start_paused = true)]
    async fn teardown_budget_starts_at_service_exit_not_process_start() {
        use std::time::Duration;

        let cancellation = CancellationToken::new();
        let service = async {
            tokio::time::sleep(Duration::from_secs(100)).await;
            Ok(())
        };
        let host = tokio::spawn(future::pending::<anyhow::Result<()>>());
        let supervisor = wait_for_cancel(cancellation.clone());
        let started = tokio::time::Instant::now();
        assert!(super::supervise_tasks(service, host, supervisor, cancellation, health(), || {
            Duration::from_secs(3)
        })
        .await
        .is_err());
        assert_eq!(started.elapsed(), Duration::from_secs(103));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_peer_cannot_hold_shutdown_open_indefinitely() {
        let cancellation = CancellationToken::new();
        let host = tokio::spawn(future::pending::<anyhow::Result<()>>());
        let supervisor = wait_for_cancel(cancellation.clone());
        let health = health();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(31),
            supervise_tasks(future::ready(Ok(())), host, supervisor, cancellation, health.clone()),
        )
        .await;
        assert!(result.is_ok(), "a stalled peer must not outlive the shutdown budget");
        assert!(result.unwrap().is_err(), "forced shutdown must not report success");
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test]
    async fn requested_shutdown_drains_service_without_false_peer_failure() {
        let cancellation = CancellationToken::new();
        let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let drain = stopped.clone();
        let child = cancellation.clone();
        let service = async move {
            child.cancelled().await;
            tokio::task::yield_now().await;
            drain.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        };
        let host = wait_for_cancel(cancellation.clone());
        let supervisor = wait_for_cancel(cancellation.clone());
        cancellation.cancel();
        let health = health();
        supervise_tasks(service, host, supervisor, cancellation, health.clone())
            .await
            .unwrap();
        assert!(stopped.load(std::sync::atomic::Ordering::Acquire));
        assert_ne!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test]
    async fn peer_failure_waits_for_service_drain_and_all_cleanup() {
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let (drained, observed) = tokio::sync::oneshot::channel();
        let service = async move {
            child.cancelled().await;
            drained.send(()).unwrap();
            Ok(())
        };
        let host = wait_for_cancel(cancellation.clone());
        let supervisor =
            tokio::spawn(async { Err(anyhow::anyhow!("injected supervisor failure")) });
        let health = health();
        let result = supervise_tasks(service, host, supervisor, cancellation, health.clone()).await;
        assert!(result.is_err());
        observed.await.unwrap();
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test]
    async fn dropping_supervision_cancels_owned_peer_tasks() {
        let cancellation = CancellationToken::new();
        let host = tokio::spawn(future::pending::<anyhow::Result<()>>());
        let host_done = host.abort_handle();
        let supervisor = tokio::spawn(future::pending::<anyhow::Result<()>>());
        let supervisor_done = supervisor.abort_handle();
        {
            let supervising = supervise_tasks(
                service_until_cancel(cancellation.clone()),
                host,
                supervisor,
                cancellation.clone(),
                health(),
            );
            tokio::pin!(supervising);
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(supervising.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        assert!(cancellation.is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !host_done.is_finished() || !supervisor_done.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer tasks must stop after owner drop");
    }

    #[tokio::test]
    async fn host_panic_cancels_and_joins_configuration_before_returning() {
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let (finished, mut completion) = tokio::sync::oneshot::channel();
        let supervisor_task = tokio::spawn(async move {
            child.cancelled().await;
            finished.send(()).unwrap();
            Ok(())
        });
        let host_task = tokio::spawn(async {
            panic!("host integration panic");
        });
        let result = supervise_tasks(
            service_until_cancel(cancellation.clone()),
            host_task,
            supervisor_task,
            cancellation.clone(),
            health(),
        )
        .await;
        let cancelled_before_return = cancellation.is_cancelled();
        let joined_before_return = completion.try_recv().is_ok();
        cancellation.cancel();
        if !joined_before_return {
            tokio::time::timeout(std::time::Duration::from_secs(1), completion)
                .await
                .unwrap()
                .unwrap();
        }
        assert!(result.is_err());
        assert!(cancelled_before_return, "host panic must not bypass sibling cleanup");
        assert!(joined_before_return, "supervision must await sibling cleanup");
    }

    #[tokio::test]
    async fn supervisor_early_return_is_fatal_and_marks_failed() {
        let health = health();
        let cancellation = CancellationToken::new();
        let host_task = wait_for_cancel(cancellation.clone());
        let supervisor_task = tokio::spawn(async { Ok(()) });

        let result = supervise_tasks(
            service_until_cancel(cancellation.clone()),
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
            service_until_cancel(cancellation.clone()),
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
            service_until_cancel(cancellation.clone()),
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
            service_until_cancel(cancellation.clone()),
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
