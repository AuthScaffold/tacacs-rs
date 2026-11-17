use std::future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{Notify, mpsc};
use tokio_stream::StreamExt;

use tacacsrs_config::source::{
    ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigDatastore, ConfigDelta,
    ConfigObservation, DatastoreRuntimePolicy, InitialLoadPolicy, StaticDatastore,
};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_config::{TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_credential_resolution::{
    CredentialChangeError, CredentialChangeEvent, CredentialChangeSource, CredentialChangeStream,
    FakeCredentialResolver,
};
use tacacsrs_provider::CredentialProvider;

use crate::{ListenerRegistration, RuntimeLifecycle, RuntimeService, ShutdownReceiver};
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
        companions: Vec::new(),
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

struct Dropped(Arc<AtomicBool>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test(start_paused = true)]
async fn domain_and_peer_cleanup_share_one_deadline_and_finish_before_return() {
    let runtime = runtime(bundle()).await;
    let service = runtime.service().clone();
    let health = runtime.health().clone();
    let (listener, listener_dropped) = listener(ListenerMode::Stall);
    let peer_dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(peer_dropped.clone());
    let peer = RuntimePeer::new("Stalled peer", move |_| async move {
        let _guard = guard;
        future::pending().await
    });
    let started = tokio::time::Instant::now();
    let error = runtime
        .run_until(tokio::time::sleep(Duration::from_secs(1)), vec![listener], vec![peer])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Shutdown deadline elapsed"));
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    assert!(listener_dropped.load(Ordering::Acquire));
    assert!(peer_dropped.load(Ordering::Acquire));
    assert!(service.ensure_open().is_err());
    assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
}

#[tokio::test(start_paused = true)]
async fn listener_failure_starts_peer_cleanup_without_a_second_budget() {
    let runtime = runtime(bundle()).await;
    let service = runtime.service().clone();
    let (failed, _) = listener(ListenerMode::Fail);
    let (stalled, dropped) = listener(ListenerMode::Stall);
    let peer = RuntimePeer::new("Stalled peer", |_| future::pending());
    let started = tokio::time::Instant::now();
    let error = runtime
        .run_until(future::pending(), vec![failed, stalled], vec![peer])
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
        let sibling = RuntimePeer::new("Sibling", move |context| async move {
            context.cancellation.cancelled().await;
            recorded.store(true, Ordering::Release);
            Ok(())
        });
        let failure = RuntimePeer::new("Critical fixture", move |_| async move {
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
    let peer = RuntimePeer::new("Cleanup fixture", |context| async move {
        context.cancellation.cancelled().await;
        anyhow::bail!("fixture cleanup failed");
    });
    let error = runtime
        .run_until(tokio::time::sleep(Duration::from_secs(1)), vec![listener], vec![peer])
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("fixture cleanup failed"));
    assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn dropping_application_cancels_owned_peers() {
    let runtime = runtime(bundle()).await;
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let peer = RuntimePeer::new("Owned fixture", move |context| async move {
        let _guard = guard;
        sender.send(context.cancellation).unwrap();
        future::pending().await
    });
    let (listener, _) = listener(ListenerMode::Drain);
    let cancellation = {
        let application = runtime.run_until(future::pending(), vec![listener], vec![peer]);
        tokio::pin!(application);
        tokio::select! {
            result = &mut application => panic!("Application returned before drop: {result:?}"),
            cancellation = receiver => cancellation.unwrap(),
        }
    };
    assert!(cancellation.is_cancelled());
    tokio::time::timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn cooperative_peers_allow_normal_and_forced_listener_cleanup() {
    for mode in [ListenerMode::Drain, ListenerMode::Stall] {
        let runtime = runtime(bundle()).await;
        let health = runtime.health().clone();
        let service = runtime.service().clone();
        let finished = Arc::new(AtomicBool::new(false));
        let recorded = finished.clone();
        let peer = RuntimePeer::new("Cooperative fixture", move |context| async move {
            context.cancellation.cancelled().await;
            recorded.store(true, Ordering::Release);
            Ok(())
        });
        let (listener, dropped) = listener(mode);
        runtime
            .run_until(tokio::time::sleep(Duration::from_secs(1)), vec![listener], vec![peer])
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
async fn primary_peer_error_survives_stalled_domain_cleanup() {
    let runtime = runtime(bundle()).await;
    let (listener, dropped) = listener(ListenerMode::Stall);
    let peer = RuntimePeer::new("Primary fixture", |_| async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        anyhow::bail!("primary peer error");
    });
    let error = runtime
        .run_until(future::pending(), vec![listener], vec![peer])
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("primary peer error"));
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
    let peer = RuntimePeer::new("Stalled fixture", |_| future::pending());
    let error = runtime
        .run_until(tokio::time::sleep(Duration::from_millis(500)), vec![listener], vec![peer])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Shutdown deadline elapsed"));
    assert_eq!(started.elapsed(), Duration::from_secs(2));
    assert!(dropped.load(Ordering::Acquire));
}

struct SelfCancelling;

#[async_trait]
impl Companion for SelfCancelling {
    fn name(&self) -> &'static str {
        "Self-cancelling companion"
    }
    async fn run(self: Box<Self>, context: CompanionContext) -> anyhow::Result<()> {
        context.cancellation.cancel();
        Ok(())
    }
}

#[tokio::test]
async fn peers_and_companions_cannot_cancel_the_application() {
    for companion in [true, false] {
        let mut source = bundle();
        let peers = if companion {
            source.companions.push(Box::new(SelfCancelling));
            Vec::new()
        } else {
            vec![RuntimePeer::new(
                "Self-cancelling peer",
                |context| async move {
                    context.cancellation.cancel();
                    Ok(())
                },
            )]
        };
        let runtime = runtime(source).await;
        let health = runtime.health().clone();
        let (listener, dropped) = listener(ListenerMode::Drain);
        let error = runtime
            .run_until(future::pending(), vec![listener], peers)
            .await
            .unwrap_err();
        let expected = if companion {
            "Self-cancelling companion stopped unexpectedly"
        } else {
            "Self-cancelling peer stopped unexpectedly"
        };
        assert!(format!("{error:#}").contains(expected));
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    }
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
        DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None)
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

struct Started(Arc<AtomicBool>);

#[async_trait]
impl Companion for Started {
    fn name(&self) -> &'static str {
        "Must not start"
    }
    async fn run(self: Box<Self>, _: CompanionContext) -> anyhow::Result<()> {
        self.0.store(true, Ordering::Release);
        Ok(())
    }
}

#[tokio::test]
async fn fail_fast_error_and_cancellation_never_start_companions_or_listeners() {
    for fail in [true, false] {
        let entered = Arc::new(Notify::new());
        let started = Arc::new(AtomicBool::new(false));
        let mut source = bundle();
        source.datastore = Arc::new(Bootstrap {
            entered: entered.clone(),
            fail,
        });
        source.companions.push(Box::new(Started(started.clone())));
        let runtime = runtime(source).await;
        let service = runtime.service().clone();
        let stop = async {
            entered.notified().await;
            if fail {
                future::pending::<()>().await;
            }
        };
        let (listener, dropped) = listener(ListenerMode::Drain);
        let result = runtime.run_until(stop, vec![listener], Vec::new()).await;
        assert_eq!(result.is_err(), fail);
        assert!(!started.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));
        assert!(service.ensure_open().is_err());
    }
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
        DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::Continuous)
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

struct Readiness {
    ready: Arc<Notify>,
    cleaned: Arc<AtomicBool>,
}

#[async_trait]
impl Companion for Readiness {
    fn name(&self) -> &'static str {
        "Readiness fixture"
    }
    async fn run(self: Box<Self>, mut context: CompanionContext) -> anyhow::Result<()> {
        loop {
            if *context.ready.borrow_and_update() {
                self.ready.notify_one();
                break;
            }
            context.ready.changed().await?;
        }
        context.cancellation.cancelled().await;
        self.cleaned.store(true, Ordering::Release);
        Ok(())
    }
}

#[tokio::test]
async fn provider_notifications_credentials_and_companion_use_the_same_runtime() {
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
    source.companions.push(Box::new(Readiness {
        ready: ready.clone(),
        cleaned: cleaned.clone(),
    }));
    let runtime = runtime(source).await;
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
        runtime.run_until(stop, vec![listener], Vec::new()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(cleaned.load(Ordering::Acquire));
}
