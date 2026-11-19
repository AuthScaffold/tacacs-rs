use std::future::{self, Future};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{Notify, mpsc};
use tokio_stream::StreamExt;

use tacacsrs_config::source::{
    ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigDatastore, ConfigDelta,
    ConfigObservation, DatastoreRuntimePolicy, StaticDatastore,
};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_config::{TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_credential_resolution::{
    CredentialChangeError, CredentialChangeEvent, CredentialChangeSource, CredentialChangeStream,
    FakeCredentialResolver,
};
use tacacsrs_lifecycle::{HostedService, ShutdownSignal};
use tacacsrs_provider::CredentialProvider;

use crate::{DatastoreState, ListenerRegistration, RuntimeLifecycle, RuntimeService, ShutdownReceiver};
use super::*;

enum ListenerMode {
    Drain,
    Stall,
    Fail,
}

struct Listener {
    mode: ListenerMode,
    dropped: Arc<AtomicBool>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

#[async_trait]
impl RuntimeListenerService for Listener {
    async fn serve(
        self: Box<Self>,
        shutdown: ShutdownReceiver,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        let registration = ListenerRegistration::new(health, RuntimeService::ClientApi);
        registration.mark_bound();
        match self.mode {
            ListenerMode::Drain => shutdown.wait().await,
            ListenerMode::Stall => future::pending().await,
            ListenerMode::Fail => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                anyhow::bail!("fixture listener failed");
            }
        }
        Ok(())
    }
}

fn listener(mode: ListenerMode) -> (Box<dyn RuntimeListenerService>, Arc<AtomicBool>) {
    let dropped = Arc::new(AtomicBool::new(false));
    (
        Box::new(Listener {
            mode,
            dropped: dropped.clone(),
        }),
        dropped,
    )
}

fn bundle() -> SourceBundle {
    SourceBundle {
        datastore: Arc::new(StaticDatastore::new(TacacsPlus::empty())),
        credentials: CredentialProvider::none(),
        local_services: LocalServices::default(),
    }
}

async fn runtime(source: SourceBundle) -> AgentRuntime {
    AgentRuntime::prepare(RuntimeInputs {
        source,
        policy: PolicyInput::Canonical(tacacsrs_config::tacacsrs::RuntimePolicy {
            shutdown_timeout_seconds: 2,
            ..Default::default()
        }),
        certificate_verification: CertificateVerification::Required,
    })
    .await
    .unwrap()
}

struct Fixture<F> {
    name: &'static str,
    run: Mutex<Option<F>>,
}

#[async_trait]
impl<F, Fut> HostedService for Fixture<F>
where
    F: FnOnce(ShutdownSignal) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    fn name(&self) -> &'static str {
        self.name
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        let run = self
            .run
            .lock()
            .unwrap()
            .take()
            .expect("The host runs each fixture once");
        run(shutdown).await
    }
}

fn hosted<F, Fut>(name: &'static str, run: F) -> Arc<dyn HostedService>
where
    F: FnOnce(ShutdownSignal) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    Arc::new(Fixture {
        name,
        run: Mutex::new(Some(run)),
    })
}

struct Dropped(Arc<AtomicBool>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test(start_paused = true)]
async fn domain_and_service_cleanup_share_one_deadline_and_finish_before_return() {
    let runtime = runtime(bundle()).await;
    let service = runtime.service().clone();
    let health = runtime.health().clone();
    let (listener, listener_dropped) = listener(ListenerMode::Stall);
    let service_dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(service_dropped.clone());
    let hosted_service = hosted("Stalled service", move |_| async move {
        let _guard = guard;
        future::pending().await
    });
    let started = tokio::time::Instant::now();
    let error = runtime
        .run_until(tokio::time::sleep(Duration::from_secs(1)), vec![listener], vec![hosted_service])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Shutdown deadline elapsed"));
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    assert!(listener_dropped.load(Ordering::Acquire));
    assert!(service_dropped.load(Ordering::Acquire));
    assert!(service.ensure_open().is_err());
    assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
}

#[tokio::test(start_paused = true)]
async fn listener_failure_starts_service_cleanup_without_a_second_budget() {
    let runtime = runtime(bundle()).await;
    let service = runtime.service().clone();
    let (failed, _) = listener(ListenerMode::Fail);
    let (stalled, dropped) = listener(ListenerMode::Stall);
    let hosted_service = hosted("Stalled service", |_| future::pending());
    let started = tokio::time::Instant::now();
    let error = runtime
        .run_until(future::pending(), vec![failed, stalled], vec![hosted_service])
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("fixture listener failed"));
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    let first = service.shutdown_deadlines().unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let second = service.shutdown_deadlines().unwrap();
    assert_eq!(first.overall.expires_at(), second.overall.expires_at());
    assert!(first.requests.expires_at() <= first.overall.expires_at());
    assert!(dropped.load(Ordering::Acquire));
    assert!(service.ensure_open().is_err());
}

#[tokio::test]
async fn critical_return_error_and_panic_are_named_and_join_siblings() {
    for mode in 0..3 {
        let runtime = runtime(bundle()).await;
        let health = runtime.health().clone();
        let finished = Arc::new(AtomicBool::new(false));
        let recorded = finished.clone();
        let sibling = hosted("Sibling", move |shutdown| async move {
            shutdown.requested().await;
            recorded.store(true, Ordering::Release);
            Ok(())
        });
        let failure = hosted("Critical fixture", move |_| async move {
            match mode {
                0 => Ok(()),
                1 => anyhow::bail!("fixture error"),
                _ => panic!("fixture panic"),
            }
        });
        let (listener, dropped) = listener(ListenerMode::Drain);
        let error = runtime
            .run_until(future::pending(), vec![listener], vec![sibling, failure])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("Critical fixture"));
        assert!(finished.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }
}

#[tokio::test(start_paused = true)]
async fn cleanup_error_survives_forced_domain_drain() {
    let runtime = runtime(bundle()).await;
    let (listener, dropped) = listener(ListenerMode::Stall);
    let hosted_service = hosted("Cleanup fixture", |shutdown| async move {
        shutdown.requested().await;
        anyhow::bail!("fixture cleanup failed");
    });
    let error = runtime
        .run_until(tokio::time::sleep(Duration::from_secs(1)), vec![listener], vec![hosted_service])
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("fixture cleanup failed"));
    assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn dropping_application_cancels_owned_services() {
    let runtime = runtime(bundle()).await;
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let hosted_service = hosted("Owned fixture", move |shutdown| async move {
        let _guard = guard;
        sender.send(shutdown).unwrap();
        future::pending().await
    });
    let (listener, _) = listener(ListenerMode::Drain);
    let cancellation = {
        let application =
            runtime.run_until(future::pending(), vec![listener], vec![hosted_service]);
        tokio::pin!(application);
        tokio::select! {
            result = &mut application => panic!("Application returned before drop: {result:?}"),
            cancellation = receiver => cancellation.unwrap(),
        }
    };
    assert!(cancellation.is_requested());
    tokio::time::timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn cooperative_services_allow_normal_and_forced_listener_cleanup() {
    for mode in [ListenerMode::Drain, ListenerMode::Stall] {
        let runtime = runtime(bundle()).await;
        let health = runtime.health().clone();
        let service = runtime.service().clone();
        let finished = Arc::new(AtomicBool::new(false));
        let recorded = finished.clone();
        let hosted_service = hosted("Cooperative fixture", move |shutdown| async move {
            shutdown.requested().await;
            recorded.store(true, Ordering::Release);
            Ok(())
        });
        let (listener, dropped) = listener(mode);
        runtime
            .run_until(
                tokio::time::sleep(Duration::from_secs(1)),
                vec![listener],
                vec![hosted_service],
            )
            .await
            .unwrap();
        assert!(finished.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
        let deadlines = service.shutdown_deadlines().unwrap();
        assert_eq!(deadlines.requests.expires_at(), deadlines.overall.expires_at());
    }
}

#[tokio::test(start_paused = true)]
async fn primary_service_error_survives_stalled_domain_cleanup() {
    let runtime = runtime(bundle()).await;
    let (listener, dropped) = listener(ListenerMode::Stall);
    let hosted_service = hosted("Primary fixture", |_| async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        anyhow::bail!("primary service error");
    });
    let error = runtime
        .run_until(future::pending(), vec![listener], vec![hosted_service])
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("primary service error"));
    assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test(start_paused = true)]
async fn domain_and_host_reuse_deadlines_across_time_and_policy_changes() {
    let runtime = runtime(bundle()).await;
    let service = runtime.service().clone();
    let started = tokio::time::Instant::now();
    let first = service.shutdown_deadlines().unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    service
        .apply_policy_candidate(Some(&tacacsrs_config::tacacsrs::RuntimePolicy {
            shutdown_timeout_seconds: 10,
            ..Default::default()
        }))
        .await
        .unwrap();
    let second = service.shutdown_deadlines().unwrap();
    assert_eq!(first.overall.expires_at(), second.overall.expires_at());
    assert_eq!(first.requests.expires_at(), second.requests.expires_at());
    let (listener, dropped) = listener(ListenerMode::Stall);
    let hosted_service = hosted("Stalled fixture", |_| future::pending());
    let error = runtime
        .run_until(
            tokio::time::sleep(Duration::from_millis(500)),
            vec![listener],
            vec![hosted_service],
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Shutdown deadline elapsed"));
    assert_eq!(started.elapsed(), Duration::from_secs(2));
    assert!(dropped.load(Ordering::Acquire));
}

struct Bootstrap {
    entered: Arc<Notify>,
    fail: bool,
}

#[async_trait]
impl ConfigDatastore for Bootstrap {
    fn label(&self) -> &'static str {
        "bootstrap-fixture"
    }
    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        DatastoreRuntimePolicy::new(ChangeNotificationMode::None)
    }
    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        unreachable!()
    }
    async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
        self.entered.notify_one();
        if self.fail {
            anyhow::bail!("fixture bootstrap failed");
        }
        future::pending().await
    }
}

#[tokio::test]
async fn unavailable_initial_configuration_still_starts_services_and_listeners() {
    let entered = Arc::new(Notify::new());
    let started = Arc::new(AtomicBool::new(false));
    let mut source = bundle();
    source.datastore = Arc::new(Bootstrap {
        entered: entered.clone(),
        fail: true,
    });
    let runtime = runtime(source).await;
    let service = runtime.service().clone();
    let health = runtime.health();
    let mut observed = health.subscribe();
    let (listener, dropped) = listener(ListenerMode::Drain);
    let recorded = started.clone();
    let service_fixture = hosted("Starts without configuration", move |shutdown| async move {
        recorded.store(true, Ordering::Release);
        shutdown.requested().await;
        Ok(())
    });
    let stop = async {
        entered.notified().await;
        observed
            .wait_for(|snapshot| {
                snapshot.is_listening() && snapshot.datastore() == DatastoreState::Unavailable
            })
            .await
            .expect("the health watch must stay open");
    };

    tokio::time::timeout(
        Duration::from_secs(5),
        runtime.run_until(stop, vec![listener], vec![service_fixture]),
    )
    .await
    .expect("the runtime must stop")
    .expect("an unavailable source must not stop the runtime");

    assert!(started.load(Ordering::Acquire));
    assert!(dropped.load(Ordering::Acquire));
    assert!(!health.snapshot().has_applied_configuration());
    assert!(service.ensure_open().is_err());
}

struct Notifications(tokio::sync::Mutex<Option<mpsc::Receiver<ConfigChangeEvent>>>);
struct Observation(mpsc::Receiver<ConfigChangeEvent>);

#[async_trait]
impl ConfigObservation for Observation {
    async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
        Ok(self.0.recv().await)
    }
}

#[async_trait]
impl ConfigDatastore for Notifications {
    fn label(&self) -> &'static str {
        "notification-fixture"
    }
    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        DatastoreRuntimePolicy::new(ChangeNotificationMode::Continuous)
    }
    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        unreachable!()
    }
    async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
        Ok(Box::new(Observation(self.0.lock().await.take().unwrap())))
    }
}

struct CredentialEvents {
    subscribed: Arc<Notify>,
}

#[async_trait]
impl CredentialChangeSource for CredentialEvents {
    async fn subscribe(&self) -> Result<CredentialChangeStream, CredentialChangeError> {
        self.subscribed.notify_one();
        Ok(Box::pin(
            tokio_stream::once(CredentialChangeEvent::Recovered).chain(tokio_stream::pending()),
        ))
    }
}

#[tokio::test]
async fn provider_notifications_credentials_and_hosted_service_use_the_same_runtime() {
    let (sender, receiver) = mpsc::channel(2);
    let baseline = TacacsPlusBuilder::new()
        .with_server_builder(
            TacacsPlusServerBuilder::new("fixture", TacacsPlusServerType::all(), "127.0.0.1", 9)
                .with_shared_secret("test-key"),
        )
        .build()
        .unwrap();
    let change = |source| {
        let config = Arc::new(source);
        ConfigChangeEvent::Changed(ConfigChange {
            delta: ConfigDelta::diff(None, &config),
            config,
        })
    };
    sender.send(change(baseline)).await.unwrap();
    let ready = Arc::new(Notify::new());
    let subscribed = Arc::new(Notify::new());
    let cleaned = Arc::new(AtomicBool::new(false));
    let mut source = bundle();
    source.datastore = Arc::new(Notifications(tokio::sync::Mutex::new(Some(receiver))));
    source.credentials = CredentialProvider::observed(
        Arc::new(FakeCredentialResolver::new()),
        Arc::new(CredentialEvents {
            subscribed: subscribed.clone(),
        }),
    );
    let runtime = runtime(source).await;
    let mut readiness = runtime.health().subscribe_readiness();
    let (signal_ready, recorded) = (ready.clone(), cleaned.clone());
    let readiness_fixture = hosted("Readiness fixture", move |shutdown| async move {
        readiness.wait_for(|ready| *ready).await?;
        signal_ready.notify_one();
        shutdown.requested().await;
        recorded.store(true, Ordering::Release);
        Ok(())
    });
    let service = runtime.service().clone();
    let (listener, _) = listener(ListenerMode::Drain);
    let stop = async {
        ready.notified().await;
        subscribed.notified().await;
        assert_eq!(service.server_count(), 1);
        sender.send(change(TacacsPlus::empty())).await.unwrap();
        while service.server_count() != 0 {
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(
        Duration::from_secs(5),
        runtime.run_until(stop, vec![listener], vec![readiness_fixture]),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(cleaned.load(Ordering::Acquire));
}
