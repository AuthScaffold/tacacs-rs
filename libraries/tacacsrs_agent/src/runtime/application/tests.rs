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

use crate::{
    DatastoreState, DegradationReason, ListenerRegistration, ListenerState, RuntimeLifecycle,
    RuntimeService, ShutdownReceiver,
};
use super::*;

enum ListenerMode {
    Drain,
    Stall,
    Fail,
    Complete,
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
    fn name(&self) -> &'static str {
        "fixture listener"
    }

    fn service(&self) -> Option<RuntimeService> {
        Some(RuntimeService::ClientApi)
    }

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
            ListenerMode::Complete => {}
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
        local_services_overlays: Vec::new(),
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

#[tokio::test(start_paused = true)]
async fn completed_listener_and_hosted_service_do_not_stop_the_application() {
    let runtime = runtime(bundle()).await;
    let health = runtime.health().clone();
    let (completed, _) = listener(ListenerMode::Complete);
    let (draining, dropped) = listener(ListenerMode::Drain);
    let short_lived = hosted("Short-lived service", |_| async { Ok(()) });
    let started = tokio::time::Instant::now();
    runtime
        .run_until(
            tokio::time::sleep(Duration::from_secs(10)),
            vec![completed, draining],
            vec![short_lived],
        )
        .await
        .unwrap();
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
}

#[tokio::test]
async fn hosted_error_and_panic_are_named_and_join_siblings() {
    for mode in 1..3 {
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
            local_services: None,
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn proxy_only(endpoint: Option<String>) -> LocalServices {
    LocalServices {
        client_api_enabled: false,
        tacacs_proxy_enabled: true,
        tacacs_proxy_endpoint: endpoint,
        ..LocalServices::default()
    }
}

async fn accepts(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

async fn eventually<F, Fut>(description: &str, condition: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{description}"));
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support TCP listeners.
async fn datastore_local_services_move_the_proxy_and_reject_invalid_values() {
    let (sender, receiver) = mpsc::channel(4);
    let servers = Arc::new(
        TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "fixture",
                    TacacsPlusServerType::all(),
                    "192.0.2.10",
                    49,
                )
                .with_shared_secret("test-key"),
            )
            .build()
            .unwrap(),
    );
    let change = |local_services: LocalServices| {
        ConfigChangeEvent::Changed(ConfigChange {
            local_services: Some(Arc::new(local_services)),
            delta: ConfigDelta::diff(None, &servers),
            config: Arc::clone(&servers),
        })
    };
    let mut source = bundle();
    source.local_services = proxy_only(None);
    source.datastore = Arc::new(Notifications(tokio::sync::Mutex::new(Some(receiver))));
    let runtime = runtime(source).await;
    let health = runtime.health().clone();
    let listener = runtime.service().tacacs_proxy_listener();
    assert_eq!(health.snapshot().listener(RuntimeService::TacacsProxy), ListenerState::Pending);

    let (first, second) = (free_port(), free_port());
    let stop = async {
        sender
            .send(change(proxy_only(Some(format!("127.0.0.1:{first}")))))
            .await
            .unwrap();
        eventually("the proxy must bind the first endpoint", move || accepts(first)).await;

        sender
            .send(change(proxy_only(Some(format!("127.0.0.1:{second}")))))
            .await
            .unwrap();
        eventually("the proxy must move to the second endpoint", move || async move {
            accepts(second).await && !accepts(first).await
        })
        .await;

        let mut invalid = proxy_only(Some(format!("127.0.0.1:{first}")));
        invalid.max_connections = 0;
        sender.send(change(invalid)).await.unwrap();
        let mut changes = health.subscribe();
        tokio::time::timeout(
            Duration::from_secs(5),
            changes.wait_for(|snapshot| {
                snapshot
                    .degradation_reasons()
                    .contains(&DegradationReason::CandidateConfigurationRejected)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(accepts(second).await, "a rejected value must keep the proxy");
        assert!(!accepts(first).await);
        assert_eq!(health.snapshot().listener(RuntimeService::TacacsProxy), ListenerState::Bound);
    };
    tokio::time::timeout(
        Duration::from_secs(10),
        runtime.run_until(stop, vec![listener], Vec::new()),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support TCP listeners.
async fn a_local_proxy_row_proxy_applies_servers_while_it_waits_for_an_endpoint() {
    use tacacsrs_config::tacacsrs::ProxyCredentialSource;

    let (sender, receiver) = mpsc::channel(4);
    let port = free_port();
    let upstream =
        TacacsPlusServerBuilder::new("fixture", TacacsPlusServerType::all(), "192.0.2.10", 49)
            .with_shared_secret("test-key");
    let local_row =
        TacacsPlusServerBuilder::new("local-proxy", TacacsPlusServerType::all(), "127.0.0.1", port)
            .with_shared_secret("proxy-key");
    let change = |servers: TacacsPlus, endpoint: Option<String>| {
        let servers = Arc::new(servers);
        ConfigChangeEvent::Changed(ConfigChange {
            local_services: Some(Arc::new(LocalServices {
                proxy_credential_source: ProxyCredentialSource::LocalProxyRow,
                ..proxy_only(endpoint)
            })),
            delta: ConfigDelta::diff(None, &servers),
            config: servers,
        })
    };
    let mut source = bundle();
    source.local_services = LocalServices {
        proxy_credential_source: ProxyCredentialSource::LocalProxyRow,
        ..proxy_only(None)
    };
    source.datastore = Arc::new(Notifications(tokio::sync::Mutex::new(Some(receiver))));
    let runtime = runtime(source).await;
    let health = runtime.health().clone();
    let listener = runtime.service().tacacs_proxy_listener();

    let stop = async {
        let waiting = TacacsPlusBuilder::new()
            .with_server_builder(upstream.clone())
            .build()
            .unwrap();
        sender.send(change(waiting, None)).await.unwrap();
        let mut changes = health.subscribe();
        let snapshot = tokio::time::timeout(
            Duration::from_secs(5),
            changes.wait_for(|snapshot| snapshot.datastore() == DatastoreState::Current),
        )
        .await
        .expect("a waiting proxy must not reject the server set")
        .unwrap()
        .clone();
        assert!(!snapshot
            .degradation_reasons()
            .contains(&DegradationReason::CandidateConfigurationRejected));
        assert_eq!(snapshot.listener(RuntimeService::TacacsProxy), ListenerState::Pending);

        let bound = TacacsPlusBuilder::new()
            .with_server_builder(upstream.clone())
            .with_server_builder(local_row.clone())
            .build()
            .unwrap();
        sender
            .send(change(bound, Some(format!("127.0.0.1:{port}"))))
            .await
            .unwrap();
        eventually("the proxy must bind after the local proxy row arrives", move || accepts(port))
            .await;
    };
    tokio::time::timeout(
        Duration::from_secs(10),
        runtime.run_until(stop, vec![listener], Vec::new()),
    )
    .await
    .unwrap()
    .unwrap();
}
