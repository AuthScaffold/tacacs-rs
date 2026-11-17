//! Host supervision for the daemon runtime lifecycle.
//!
//! [`run_until`] drives one host stop future and the application together. It
//! builds the service through [`crate::startup::prepare_service`], then
//! [`PreparedService::run`] starts the service, host integration, and the
//! configuration supervisor as peers. [`supervise_registered_tasks`] observes those peers,
//! applies one shutdown budget, and joins every task before it returns.
//!
//! This module composes the agent runtime. It does not route requests or
//! materialize credentials. Those algorithms live in the agent library.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures_util::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use tokio_util::sync::CancellationToken;

use tacacsrs_agent::runtime::{ConfigSupervisor, PolicySupervisor, TacacsPlusFilter};
use tacacsrs_agent::{RuntimeHealthPublisher, RuntimeLifecycle, TacacsClientService};
use tacacsrs_config::source::policy::FilePolicyObservation;
use tacacsrs_config::source::{ConfigDatastore, InitialLoadPolicy};

use crate::client_api_listener;
use crate::credential_provider::CredentialProvider;
use crate::host_integration::HostIntegration;
use crate::startup::prepare_service;
use crate::statistics;
use crate::host_service::{HostContext, HostService};
use crate::profiles::SelectedProfile;

/// Startup-composed runtime that the host supervises until shutdown.
pub(crate) struct PreparedService {
    pub(crate) datastore: Arc<dyn ConfigDatastore>,
    pub(crate) service: Arc<TacacsClientService>,
    pub(crate) health: RuntimeHealthPublisher,
    pub(crate) config_filter: Arc<dyn TacacsPlusFilter>,
    pub(crate) credential_provider: CredentialProvider,
    pub(crate) host_integration: HostIntegration,
    pub(crate) policy_observation: Option<FilePolicyObservation>,
    pub(crate) statistics_file: Option<statistics::StatisticsFile>,
    pub(crate) host_services: Vec<Box<dyn HostService>>,
}

impl PreparedService {
    pub(crate) async fn run(self, cancellation: CancellationToken) -> anyhow::Result<()> {
        let Self {
            datastore,
            service,
            health,
            config_filter,
            credential_provider,
            host_integration,
            policy_observation,
            statistics_file,
            host_services,
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
            let statistics_service = service.clone();
            let health = health.subscribe();
            tokio::spawn(async move {
                let reporting = async {
                    if let Some(file) = statistics_file {
                        file.run(statistics_service, cancellation.clone()).await
                    } else {
                        cancellation.cancelled().await;
                        Ok(())
                    }
                };
                tokio::try_join!(host_integration.run(health, cancellation.clone()), reporting)?;
                Ok(())
            })
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
        let mut peers = vec![
            NamedTask::new("Host integration", host_task),
            NamedTask::new("Configuration supervisor", supervisor_task),
        ];
        for host_service in host_services {
            let context = HostContext {
                health: health.subscribe(),
                cancellation: cancellation.clone(),
            };
            peers.push(NamedTask::host_service(host_service, context));
        }

        let client_api_listeners = client_api_listener::client_api_listeners(&service);
        supervise_registered_tasks(
            service.serve_until(cancellation.cancelled(), client_api_listeners),
            peers,
            cancellation.clone(),
            health,
            || service.shutdown_timeout(),
        )
        .await
    }
}

/// Coordinates named critical peers under one shutdown deadline.
async fn supervise_registered_tasks(
    service_future: impl std::future::Future<Output = anyhow::Result<()>>,
    tasks: Vec<NamedTask>,
    cancellation: CancellationToken,
    health: RuntimeHealthPublisher,
    shutdown_timeout: impl FnOnce() -> Duration,
) -> anyhow::Result<()> {
    let mut peers = PeerTasks::new(tasks, cancellation.clone());
    let mut service_future = Box::pin(service_future);

    let mut service_completed = false;
    let mut peer_failed = false;
    let mut service_result = tokio::select! {
        biased;
        () = cancellation.cancelled() => Ok(()),
        result = &mut service_future => { service_completed = true; result },
        Some((name, result)) = peers.pending.next() => {
            peer_failed = true;
            // Publish a typed failure without embedding the underlying configuration or credential error.
            health.set_lifecycle(RuntimeLifecycle::Failed);
            Err(peer_exit_to_fatal_error(name, result))
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
        while !service_completed || !peers.pending.is_empty() {
            let result = tokio::select! {
                biased;
                result = &mut service_future, if !service_completed => {
                    service_completed = true;
                    result
                }
                Some((name, result)) = peers.pending.next() => {
                    let result = result.with_context(|| format!("{name} task panicked"))
                        .and_then(std::convert::identity);
                    peer_failed |= result.is_err();
                    result
                }
            };
            if service_result.is_ok() {
                service_result = result;
            }
        }
    };
    if tokio::time::timeout_at(deadline, cleanup).await.is_err() {
        health.set_lifecycle(RuntimeLifecycle::Failed);
        drop(service_future);
        peers.abort_all();
        while peers.pending.next().await.is_some() {}
        return service_result.and(Err(anyhow::anyhow!("Shutdown deadline elapsed")));
    }

    if peer_failed {
        health.set_lifecycle(RuntimeLifecycle::Failed);
    }
    service_result
}

pub(crate) struct NamedTask {
    name: &'static str,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl NamedTask {
    fn host_service(service: Box<dyn HostService>, context: HostContext) -> Self {
        Self::new(service.name(), tokio::spawn(service.run(context)))
    }

    pub(crate) fn new(
        name: &'static str,
        handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    ) -> Self {
        Self { name, handle }
    }
}

type PeerOutcome = (&'static str, Result<anyhow::Result<()>, tokio::task::JoinError>);

struct PeerTasks {
    cancellation: CancellationToken,
    aborts: Vec<tokio::task::AbortHandle>,
    pending: FuturesUnordered<BoxFuture<'static, PeerOutcome>>,
}

impl PeerTasks {
    fn new(tasks: Vec<NamedTask>, cancellation: CancellationToken) -> Self {
        let aborts = tasks
            .iter()
            .map(|task| task.handle.abort_handle())
            .collect();
        let pending = tasks
            .into_iter()
            .map(|task| async move { (task.name, task.handle.await) }.boxed())
            .collect();
        Self {
            cancellation,
            aborts,
            pending,
        }
    }

    fn abort_all(&self) {
        for task in &self.aborts {
            task.abort();
        }
    }
}

impl Drop for PeerTasks {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.abort_all();
    }
}

/// Classifies an unexpected configuration-supervisor task outcome as a fatal error.
fn peer_exit_to_fatal_error(
    name: &'static str,
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow::anyhow!("{name} stopped unexpectedly"),
        Ok(Err(error)) => error.context(format!("{name} failed")),
        Err(join_error) => anyhow::Error::new(join_error).context(format!("{name} task panicked")),
    }
}

/// Drives the host stop future and the application together.
///
/// The host stop future wins the race only after it cancels the shared token
/// and the application drains. The application owns startup composition and the
/// supervised runtime. The service cannot reopen after this returns.
///
/// # Errors
/// Returns a startup, supervision, or cleanup error after the application drains.
pub(crate) async fn run_until(
    profile: SelectedProfile,
    stop: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let application = async {
        let prepared = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            prepared = prepare_service(profile) => prepared?,
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

#[cfg(test)]
async fn supervise_tasks(
    service: impl std::future::Future<Output = anyhow::Result<()>>,
    host: tokio::task::JoinHandle<anyhow::Result<()>>,
    supervisor: tokio::task::JoinHandle<anyhow::Result<()>>,
    cancellation: CancellationToken,
    health: RuntimeHealthPublisher,
    shutdown_timeout: impl FnOnce() -> Duration,
) -> anyhow::Result<()> {
    supervise_registered_tasks(
        service,
        vec![
            NamedTask::new("Host integration", host),
            NamedTask::new("Configuration supervisor", supervisor),
        ],
        cancellation,
        health,
        shutdown_timeout,
    )
    .await
}

#[cfg(test)]
mod supervision_tests {
    use std::future;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    use tacacsrs_agent::{EnabledServices, RuntimeHealthPublisher, RuntimeLifecycle};
    use tokio_util::sync::CancellationToken;

    use crate::host_service::{HostContext, HostService};
    use super::{NamedTask, supervise_registered_tasks};

    struct RegisteredService {
        name: &'static str,
        fail: bool,
        cleanup: Arc<AtomicBool>,
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl HostService for RegisteredService {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn run(self: Box<Self>, context: HostContext) -> anyhow::Result<()> {
            if self.fail {
                anyhow::bail!("registered service failure");
            }
            context.cancellation.cancelled().await;
            tokio::time::sleep(self.delay).await;
            self.cleanup.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn registered_service_failure_cancels_and_joins_every_peer() {
        let cancellation = CancellationToken::new();
        let health = health();
        let cleaned = Arc::new(AtomicBool::new(false));
        let mut tasks = vec![
            NamedTask::new("Host integration", wait_for_cancel(cancellation.clone())),
            NamedTask::new("Configuration supervisor", wait_for_cancel(cancellation.clone())),
        ];
        for service in [
            RegisteredService {
                name: "Fixture worker",
                fail: false,
                cleanup: cleaned.clone(),
                delay: Duration::from_secs(1),
            },
            RegisteredService {
                name: "Fixture registrar",
                fail: true,
                cleanup: Arc::new(AtomicBool::new(false)),
                delay: Duration::ZERO,
            },
        ] {
            tasks.push(NamedTask::host_service(
                Box::new(service),
                HostContext {
                    health: health.subscribe(),
                    cancellation: cancellation.clone(),
                },
            ));
        }
        let started = tokio::time::Instant::now();
        let error = supervise_registered_tasks(
            service_until_cancel(cancellation.clone()),
            tasks,
            cancellation.clone(),
            health.clone(),
            || Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("Fixture registrar failed"));
        assert!(cleaned.load(Ordering::Acquire));
        assert!(cancellation.is_cancelled());
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_registered_service_cannot_extend_the_captured_shutdown_budget() {
        let cancellation = CancellationToken::new();
        let health = health();
        let cleaned = Arc::new(AtomicBool::new(false));
        let slow = NamedTask::host_service(
            Box::new(RegisteredService {
                name: "Slow fixture",
                fail: false,
                cleanup: cleaned.clone(),
                delay: Duration::from_secs(60),
            }),
            HostContext {
                health: health.subscribe(),
                cancellation: cancellation.clone(),
            },
        );
        let finished = slow.handle.abort_handle();
        let tasks = vec![
            NamedTask::new("Host integration", wait_for_cancel(cancellation.clone())),
            NamedTask::new("Configuration supervisor", wait_for_cancel(cancellation.clone())),
            slow,
        ];
        cancellation.cancel();
        let started = tokio::time::Instant::now();
        let error = supervise_registered_tasks(
            future::ready(Ok(())),
            tasks,
            cancellation,
            health.clone(),
            || Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Shutdown deadline elapsed"));
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert!(finished.is_finished());
        assert!(!cleaned.load(Ordering::Acquire));
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_errors_remain_primary_while_a_listener_stalls() {
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let cleanup = NamedTask::new(
            "Fixture cleanup",
            tokio::spawn(async move {
                child.cancelled().await;
                Err(anyhow::anyhow!("registration cleanup failed"))
            }),
        );
        cancellation.cancel();
        let error = supervise_registered_tasks(
            future::pending(),
            vec![cleanup],
            cancellation,
            health(),
            || Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("registration cleanup failed"));
    }

    fn supervisor_exit_to_fatal_error(
        result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    ) -> anyhow::Error {
        super::peer_exit_to_fatal_error("Configuration supervisor", result)
    }

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
