use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::FutureExt;
use tacacsrs_config::tacacsrs::LocalServices;
use tokio::sync::{watch, Notify};

use super::*;
use crate::runtime::shutdown::ShutdownCoordinator;
use crate::EnabledServices;

#[derive(Clone, Default)]
struct FakeInstances {
    log: Arc<Mutex<Vec<String>>>,
    failures: Arc<Mutex<HashMap<String, usize>>>,
    crashing: Arc<Mutex<HashSet<String>>>,
    crash: Arc<Notify>,
}

impl FakeInstances {
    fn events(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn position(&self, event: &str) -> usize {
        self.events()
            .iter()
            .position(|entry| entry == event)
            .unwrap_or_else(|| panic!("the log must contain {event:?}: {:?}", self.events()))
    }

    async fn wait_for(&self, event: &str) {
        tokio::time::timeout(Duration::from_secs(60), async {
            while !self.events().iter().any(|entry| entry == event) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the log must contain {event:?}: {:?}", self.events()));
    }
}

impl ListenerInstances for FakeInstances {
    type Target = String;

    fn service(&self) -> RuntimeService {
        RuntimeService::TacacsProxy
    }

    fn desired(&self, local: &ActiveLocalServices) -> DesiredListener<String> {
        let settings = local.settings();
        match (&settings.tacacs_proxy_endpoint, settings.tacacs_proxy_enabled) {
            (_, false) => DesiredListener::Disabled,
            (None, true) => DesiredListener::Waiting,
            (Some(endpoint), true) => DesiredListener::Ready(endpoint.clone()),
        }
    }

    fn conflicts(&self, active: &String, next: &String) -> bool {
        let port = |target: &String| target.parse::<SocketAddr>().unwrap().port();
        port(active) == port(next)
    }

    fn start(
        &self,
        target: String,
        shutdown: ShutdownReceiver,
        bound: BindSignal,
    ) -> BoxFuture<'static, anyhow::Result<()>> {
        let fake = self.clone();
        async move {
            fake.log.lock().unwrap().push(format!("start {target}"));
            let fail = fake
                .failures
                .lock()
                .unwrap()
                .get_mut(&target)
                .is_some_and(|remaining| {
                    let fail = *remaining > 0;
                    *remaining = remaining.saturating_sub(1);
                    fail
                });
            if fail {
                fake.log.lock().unwrap().push(format!("fail {target}"));
                anyhow::bail!("the endpoint {target} is in use");
            }
            bound.mark_bound();
            fake.log.lock().unwrap().push(format!("bound {target}"));
            if fake.crashing.lock().unwrap().contains(&target) {
                tokio::select! {
                    () = fake.crash.notified() => anyhow::bail!("the listener {target} crashed"),
                    () = shutdown.wait() => {}
                }
            } else {
                shutdown.wait().await;
            }
            fake.log.lock().unwrap().push(format!("stop {target}"));
            Ok(())
        }
        .boxed()
    }
}

fn local(enabled: bool, endpoint: Option<&str>) -> Arc<ActiveLocalServices> {
    Arc::new(
        ActiveLocalServices::new(LocalServices {
            tacacs_proxy_enabled: enabled,
            tacacs_proxy_endpoint: endpoint.map(str::to_owned),
            ..LocalServices::default()
        })
        .unwrap(),
    )
}

struct Harness {
    fake: FakeInstances,
    local: watch::Sender<Arc<ActiveLocalServices>>,
    health: RuntimeHealthPublisher,
    shutdown: ShutdownCoordinator,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Harness {
    fn start(fake: FakeInstances, initial: Arc<ActiveLocalServices>) -> Self {
        let health = RuntimeHealthPublisher::new(EnabledServices::BOTH);
        let (local, receiver) = watch::channel(initial);
        let shutdown = ShutdownCoordinator::new(health.clone());
        let task =
            tokio::spawn(reconcile(fake.clone(), receiver, shutdown.subscribe(), health.clone()));
        Self {
            fake,
            local,
            health,
            shutdown,
            task,
        }
    }

    async fn wait_for_state(&self, state: ListenerState) {
        let mut changes = self.health.subscribe();
        tokio::time::timeout(
            Duration::from_secs(60),
            changes.wait_for(|snapshot| snapshot.listener(RuntimeService::TacacsProxy) == state),
        )
        .await
        .unwrap_or_else(|_| panic!("the proxy listener must reach {state:?}"))
        .unwrap();
    }

    fn state(&self) -> ListenerState {
        self.health.snapshot().listener(RuntimeService::TacacsProxy)
    }

    async fn stop(self) -> anyhow::Result<()> {
        self.shutdown.initiate_shutdown();
        tokio::time::timeout(Duration::from_secs(60), self.task)
            .await
            .expect("the reconciler must stop")
            .unwrap()
    }
}

const FIRST: &str = "127.0.0.1:4901";
const SECOND: &str = "127.0.0.1:4902";
const SAME_PORT: &str = "0.0.0.0:4901";

#[tokio::test(start_paused = true)]
async fn a_moved_listener_binds_before_the_old_listener_stops() {
    let harness = Harness::start(FakeInstances::default(), local(true, Some(FIRST)));
    harness.fake.wait_for(&format!("bound {FIRST}")).await;
    harness.wait_for_state(ListenerState::Bound).await;

    harness.local.send_replace(local(true, Some(SECOND)));
    harness.fake.wait_for(&format!("stop {FIRST}")).await;

    let fake = harness.fake.clone();
    assert!(fake.position(&format!("bound {SECOND}")) < fake.position(&format!("stop {FIRST}")));
    assert_eq!(harness.state(), ListenerState::Bound);
    harness.stop().await.unwrap();
    assert!(fake.events().contains(&format!("stop {SECOND}")));
}

#[tokio::test(start_paused = true)]
async fn a_conflicting_target_stops_the_old_listener_first() {
    let harness = Harness::start(FakeInstances::default(), local(true, Some(FIRST)));
    harness.fake.wait_for(&format!("bound {FIRST}")).await;

    harness.local.send_replace(local(true, Some(SAME_PORT)));
    harness.fake.wait_for(&format!("bound {SAME_PORT}")).await;

    let fake = harness.fake.clone();
    assert!(fake.position(&format!("stop {FIRST}")) < fake.position(&format!("start {SAME_PORT}")));
    harness.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_bind_failure_keeps_the_old_listener_and_tries_again() {
    let fake = FakeInstances::default();
    fake.failures.lock().unwrap().insert(SECOND.to_owned(), 2);
    let harness = Harness::start(fake, local(true, Some(FIRST)));
    harness.fake.wait_for(&format!("bound {FIRST}")).await;

    let started = tokio::time::Instant::now();
    harness.local.send_replace(local(true, Some(SECOND)));
    harness.fake.wait_for(&format!("bound {SECOND}")).await;
    harness.fake.wait_for(&format!("stop {FIRST}")).await;

    let fake = harness.fake.clone();
    let failures = fake
        .events()
        .iter()
        .filter(|entry| **entry == format!("fail {SECOND}"))
        .count();
    assert_eq!(failures, 2);
    assert!(fake.position(&format!("bound {SECOND}")) < fake.position(&format!("stop {FIRST}")));
    assert!(started.elapsed() >= INITIAL_BIND_RETRY * 3, "the retries must wait 1 s, then 2 s");
    assert_eq!(harness.state(), ListenerState::Bound);
    harness.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_failed_move_is_not_ready_until_the_desired_target_is_served() {
    let fake = FakeInstances::default();
    fake.failures
        .lock()
        .unwrap()
        .insert(SECOND.to_owned(), usize::MAX);
    let harness = Harness::start(fake, local(true, Some(FIRST)));
    harness.fake.wait_for(&format!("bound {FIRST}")).await;
    harness.wait_for_state(ListenerState::Bound).await;

    harness.local.send_replace(local(true, Some(SECOND)));
    harness.fake.wait_for(&format!("fail {SECOND}")).await;
    harness.wait_for_state(ListenerState::Binding).await;

    harness.local.send_replace(local(true, Some(FIRST)));
    harness.wait_for_state(ListenerState::Bound).await;
    let fake = harness.fake.clone();
    let starts = fake
        .events()
        .iter()
        .filter(|entry| **entry == format!("start {FIRST}"))
        .count();
    assert_eq!(starts, 1, "the old listener must keep serving");
    harness.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_new_target_does_not_wait_for_the_retry_of_a_failed_target() {
    let fake = FakeInstances::default();
    fake.failures
        .lock()
        .unwrap()
        .insert(FIRST.to_owned(), usize::MAX);
    let harness = Harness::start(fake, local(true, Some(FIRST)));
    harness.fake.wait_for(&format!("fail {FIRST}")).await;
    assert_eq!(harness.state(), ListenerState::Binding);

    let started = tokio::time::Instant::now();
    harness.local.send_replace(local(true, Some(SECOND)));
    harness.fake.wait_for(&format!("bound {SECOND}")).await;

    assert!(started.elapsed() < INITIAL_BIND_RETRY);
    harness.wait_for_state(ListenerState::Bound).await;
    harness.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn disable_and_waiting_states_stop_the_listener() {
    let harness = Harness::start(FakeInstances::default(), local(true, Some(FIRST)));
    harness.fake.wait_for(&format!("bound {FIRST}")).await;

    harness.local.send_replace(local(true, None));
    harness.fake.wait_for(&format!("stop {FIRST}")).await;
    harness.wait_for_state(ListenerState::Pending).await;

    harness.local.send_replace(local(true, Some(SECOND)));
    harness.fake.wait_for(&format!("bound {SECOND}")).await;
    harness.wait_for_state(ListenerState::Bound).await;

    harness.local.send_replace(local(false, None));
    harness.fake.wait_for(&format!("stop {SECOND}")).await;
    harness.wait_for_state(ListenerState::Disabled).await;

    harness.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_error_from_the_active_listener_stops_the_reconciler() {
    let fake = FakeInstances::default();
    fake.crashing.lock().unwrap().insert(FIRST.to_owned());
    let harness = Harness::start(fake, local(true, Some(FIRST)));
    harness.fake.wait_for(&format!("bound {FIRST}")).await;

    harness.fake.crash.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(60), harness.task)
        .await
        .expect("the reconciler must stop")
        .unwrap()
        .expect_err("the listener error must stop the reconciler");

    assert!(format!("{error:#}").contains("crashed"), "{error:#}");
    assert_eq!(
        harness
            .health
            .snapshot()
            .listener(RuntimeService::TacacsProxy),
        ListenerState::Stopped
    );
}

#[test]
fn tcp_endpoints_conflict_on_a_shared_port() {
    let tcp = |value: &str| ListenerEndpoint::Tcp(value.parse().unwrap());
    let unix = |value: &str| ListenerEndpoint::Unix(value.into());
    assert!(endpoints_conflict(&tcp("127.0.0.1:49"), &tcp("127.0.0.1:49")));
    assert!(endpoints_conflict(&tcp("0.0.0.0:49"), &tcp("127.0.0.1:49")));
    assert!(endpoints_conflict(&tcp("127.0.0.1:49"), &tcp("[::]:49")));
    assert!(!endpoints_conflict(&tcp("127.0.0.1:49"), &tcp("127.0.0.2:49")));
    assert!(!endpoints_conflict(&tcp("127.0.0.1:0"), &tcp("127.0.0.1:0")));
    assert!(endpoints_conflict(&unix("/run/a.sock"), &unix("/run/a.sock")));
    assert!(!endpoints_conflict(&unix("/run/a.sock"), &unix("/run/b.sock")));
    assert!(!endpoints_conflict(&unix("/run/a.sock"), &tcp("127.0.0.1:49")));
}

#[tokio::test(start_paused = true)]
async fn a_service_without_a_listener_is_not_ready_while_enabled() {
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let (local_sender, receiver) = watch::channel(local(false, None));
    let shutdown = ShutdownCoordinator::new(health.clone());
    let task = tokio::spawn(report_missing_listener(
        RuntimeService::TacacsProxy,
        receiver,
        shutdown.subscribe(),
        health.clone(),
    ));
    let changes = health.subscribe();
    let wait_for = |state: ListenerState| {
        let mut changes = changes.clone();
        async move {
            tokio::time::timeout(
                Duration::from_secs(60),
                changes
                    .wait_for(|snapshot| snapshot.listener(RuntimeService::TacacsProxy) == state),
            )
            .await
            .unwrap()
            .unwrap();
        }
    };
    wait_for(ListenerState::Disabled).await;

    local_sender.send_replace(local(true, Some(FIRST)));
    wait_for(ListenerState::Pending).await;
    assert!(health.snapshot().enabled_services().tacacs_proxy());

    local_sender.send_replace(local(false, None));
    wait_for(ListenerState::Disabled).await;
    shutdown.initiate_shutdown();
    task.await.unwrap().unwrap();
}
