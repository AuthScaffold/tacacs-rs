//! Acceptance tests for host composition.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dill::component;
use tokio_util::sync::CancellationToken;

use crate::{DiagnosticsHandle, PolicyInput};
use tacacsrs_composition::{Component, Composition, Named, Value};
use tacacsrs_config::source::StaticDatastore;
use tacacsrs_config::tacacsrs::{LocalServices, RuntimePolicy};
use tacacsrs_config::{
    EpskSupportedHash, TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType, Tls13Epsk,
    TlsClientClientIdentity,
};
use tacacsrs_lifecycle::{
    ApplicationReadiness, BoxError, EmptyGroup, HealthCheck, HealthCheckContext, HealthCheckResult,
    HealthGroup, HealthGroupKind, HealthMember, HostedService, ShutdownSignal,
};
use tacacsrs_networking::CertificateVerification;
use tacacsrs_provider::{CredentialProvider, SourceDatastore};

use super::{bootstrap, run_until, StartupCheck};
use crate::components::{InvalidSourceShutdownComponent, TacacsProxyComponent};

const SOURCE: &str = "fixture source";

/// A static source with one upstream server and a TCP proxy listener.
struct FixtureSource;

impl Component for FixtureSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let config = TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "fixture",
                    TacacsPlusServerType::all(),
                    "127.0.0.1",
                    49,
                )
                .with_shared_secret("test-key"),
            )
            .build()?;
        composition.shared(Arc::new(SourceDatastore(Arc::new(StaticDatastore::new(config)))))?;
        composition.shared(Arc::new(CredentialProvider::none()))?;
        composition.shared(Arc::new(LocalServices {
            client_api_enabled: false,
            tacacs_proxy_enabled: true,
            tacacs_proxy_endpoint: Some("127.0.0.1:0".to_owned()),
            ..LocalServices::default()
        }))
    }
}

fn components(extra: Vec<Box<dyn Component>>) -> Vec<Box<dyn Component>> {
    let mut components: Vec<Box<dyn Component>> = vec![
        Box::new(Value::new("runtime policy", PolicyInput::Canonical(RuntimePolicy::default()))),
        Box::new(Value::new("certificate verification", CertificateVerification::Required)),
        Box::new(FixtureSource),
        Box::new(TacacsProxyComponent),
    ];
    components.extend(extra);
    components
}

#[derive(Default)]
struct FixtureState {
    constructed: AtomicUsize,
    runs: AtomicUsize,
    healthy_runs: AtomicUsize,
}

struct FixtureGroup;
impl HealthGroupKind for FixtureGroup {
    const NAME: &'static str = "fixture-readiness";
    const EMPTY: EmptyGroup = EmptyGroup::Reject;
}

/// Adds the host readiness to the fixture group.
struct ReadinessMember(Arc<ApplicationReadiness>);

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<FixtureGroup>)]
impl ReadinessMember {
    fn new(readiness: Arc<ApplicationReadiness>) -> Self {
        Self(readiness)
    }
}

impl Named for ReadinessMember {
    const NAME: &'static str = ApplicationReadiness::NAME;
}

#[async_trait]
impl HealthCheck for ReadinessMember {
    async fn check(&self, context: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
        self.0.check(context).await
    }
}

impl HealthMember<FixtureGroup> for ReadinessMember {
    fn name(&self) -> &'static str {
        Self::NAME
    }
}

struct FixtureService {
    state: Arc<FixtureState>,
    members: Vec<Arc<dyn HealthMember<FixtureGroup>>>,
    diagnostics: Arc<DiagnosticsHandle>,
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
impl FixtureService {
    fn new(
        state: Arc<FixtureState>,
        members: Vec<Arc<dyn HealthMember<FixtureGroup>>>,
        diagnostics: Arc<DiagnosticsHandle>,
    ) -> Self {
        state.constructed.fetch_add(1, Ordering::AcqRel);
        Self {
            state,
            members,
            diagnostics,
        }
    }
}

impl Named for FixtureService {
    const NAME: &'static str = "Fixture";
}

#[async_trait]
impl HostedService for FixtureService {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        self.diagnostics.statistics()?;
        let group = HealthGroup::<FixtureGroup>::new(self.members.clone())?;
        self.state.runs.fetch_add(1, Ordering::AcqRel);
        if group.wait_until_healthy(&shutdown).await {
            self.state.healthy_runs.fetch_add(1, Ordering::AcqRel);
        }
        shutdown.requested().await;
        Ok(())
    }
}

/// A component with a dependency, a health member, and a hosted service.
struct FixtureComponent {
    state: Arc<FixtureState>,
}

impl Component for FixtureComponent {
    fn name(&self) -> &'static str {
        FixtureService::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.shared(self.state)?;
        composition.require_group::<FixtureGroup>();
        composition.health_member::<FixtureGroup, ReadinessMember, _>(
            <ReadinessMember as dill::Component>::builder(),
        )?;
        composition.hosted_service(<FixtureService as dill::Component>::builder())
    }
}

#[tokio::test]
async fn added_component_reads_deferred_values_and_runs_after_bootstrap() {
    let state = Arc::new(FixtureState::default());
    let host = bootstrap(components(vec![Box::new(FixtureComponent {
        state: state.clone(),
    })]))
    .await
    .unwrap();
    assert_eq!(state.constructed.load(Ordering::Acquire), 1);
    assert_eq!(state.runs.load(Ordering::Acquire), 0, "Bootstrap must not start services");
    let cancellation = CancellationToken::new();
    let stop = cancellation.clone();
    let task = tokio::spawn(async move { host.run_until(stop.cancelled_owned()).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.healthy_runs.load(Ordering::Acquire) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("The service must observe the application readiness");
    cancellation.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(state.runs.load(Ordering::Acquire), 1);
}

/// A static source that the runtime always rejects.
///
/// The server uses a central keystore reference, and the source has no
/// credential resolver.
struct InvalidSource;

impl Component for InvalidSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let mut config = TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "fixture",
                    TacacsPlusServerType::all(),
                    "127.0.0.1",
                    449,
                )
                .with_shared_secret("test-key"),
            )
            .build()?;
        let server = &mut config.server[0];
        server.shared_secret = None;
        server.client_identity = Some(TlsClientClientIdentity {
            credentials_reference: None,
            certificate: None,
            tls13_epsk: Some(Tls13Epsk {
                inline_definition: None,
                central_keystore_reference: Some("missing".to_owned()),
                external_identity: "client".to_owned(),
                hash: EpskSupportedHash::Sha256,
                context: None,
                target_protocol: None,
                target_kdf: None,
                psk_dhe_ke_groups: Vec::new(),
            }),
        });
        composition.shared(Arc::new(SourceDatastore(Arc::new(StaticDatastore::new(config)))))?;
        composition.shared(Arc::new(CredentialProvider::none()))?;
        composition.shared(Arc::new(LocalServices {
            client_api_enabled: false,
            tacacs_proxy_enabled: true,
            tacacs_proxy_endpoint: Some("127.0.0.1:0".to_owned()),
            ..LocalServices::default()
        }))
    }
}

#[tokio::test]
async fn invalid_static_source_stops_the_application_with_an_error() {
    let components: Vec<Box<dyn Component>> = vec![
        Box::new(Value::new("runtime policy", PolicyInput::Canonical(RuntimePolicy::default()))),
        Box::new(Value::new("certificate verification", CertificateVerification::Required)),
        Box::new(InvalidSource),
        Box::new(TacacsProxyComponent),
        Box::new(InvalidSourceShutdownComponent),
    ];
    let result =
        tokio::time::timeout(Duration::from_secs(5), run_until(components, std::future::pending()))
            .await
            .expect("The invalid source must stop the application");
    let error = result.expect_err("The application must stop with an error");
    assert!(
        error
            .to_string()
            .contains("source configuration is invalid"),
        "{error:#}"
    );
}

#[tokio::test]
async fn enabled_service_without_a_listener_fails_bootstrap() {
    let components: Vec<Box<dyn Component>> = vec![
        Box::new(Value::new("runtime policy", PolicyInput::Canonical(RuntimePolicy::default()))),
        Box::new(Value::new("certificate verification", CertificateVerification::Required)),
        Box::new(FixtureSource),
    ];
    let Err(error) = bootstrap(components).await else {
        panic!("An enabled proxy without a listener component must fail bootstrap");
    };
    assert!(
        format!("{error:#}")
            .contains("enables the TACACS+ proxy, but no component supplies its listener"),
        "{error:#}"
    );
}

#[tokio::test]
async fn lifetime_stop_ends_the_application_successfully() {
    let host = bootstrap(components(Vec::new())).await.unwrap();
    let lifetime = host.lifetime().clone();
    let task = tokio::spawn(host.run_until(std::future::pending()));
    lifetime.stop();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("A lifetime stop must stop the application")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn missing_source_fails_before_runtime_preparation() {
    let components: Vec<_> = components(Vec::new())
        .into_iter()
        .filter(|component| component.name() != SOURCE)
        .collect();
    let error = bootstrap(components).await.err().unwrap();
    assert!(format!("{error:#}").contains("SourceDatastore"), "{error:#}");
}

struct FailingCheck;

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn StartupCheck)]
impl FailingCheck {
    fn new(
        local_services: Arc<crate::LocalServicesView>,
        runtime_policy: Arc<crate::RuntimePolicyView>,
    ) -> Self {
        drop((local_services, runtime_policy));
        Self
    }
}

impl Named for FailingCheck {
    const NAME: &'static str = "failing";
}

#[async_trait]
impl StartupCheck for FailingCheck {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn check(&self) -> anyhow::Result<()> {
        anyhow::bail!("fixture check failure")
    }
}

struct CheckComponent(Arc<FixtureState>);

impl Component for CheckComponent {
    fn name(&self) -> &'static str {
        "check"
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.member::<dyn StartupCheck, FailingCheck, _>(
            <FailingCheck as dill::Component>::builder(),
        )?;
        Box::new(FixtureComponent { state: self.0 }).register(composition)
    }
}

#[tokio::test]
async fn failed_startup_check_stops_before_service_construction() {
    let state = Arc::new(FixtureState::default());
    let error = bootstrap(components(vec![Box::new(CheckComponent(state.clone()))]))
        .await
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("fixture check failure"), "{error:#}");
    assert_eq!(state.constructed.load(Ordering::Acquire), 0);
}

#[test]
fn bootstrap_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&bootstrap(Vec::new()));
    assert_send(&super::run_until(Vec::new(), async { Ok(()) }));
}

struct ChangeObservation(tokio::sync::mpsc::Receiver<tacacsrs_config::source::ConfigChangeEvent>);

#[async_trait]
impl tacacsrs_config::source::ConfigObservation for ChangeObservation {
    async fn next(&mut self) -> anyhow::Result<Option<tacacsrs_config::source::ConfigChangeEvent>> {
        Ok(self.0.recv().await)
    }
}

/// A datastore that sends each change from the test.
struct ChangeDatastore(
    tokio::sync::Mutex<
        Option<tokio::sync::mpsc::Receiver<tacacsrs_config::source::ConfigChangeEvent>>,
    >,
);

#[async_trait]
impl tacacsrs_config::source::ConfigDatastore for ChangeDatastore {
    fn label(&self) -> &'static str {
        "change fixture"
    }

    fn behavior(&self) -> tacacsrs_config::source::SourceBehavior {
        tacacsrs_config::source::SourceBehavior::new(
            tacacsrs_config::source::ChangeNotificationMode::Continuous,
        )
    }

    async fn load(&self) -> anyhow::Result<tacacsrs_config::TacacsPlus> {
        anyhow::bail!("the fixture only sends changes")
    }

    async fn observe(&self) -> anyhow::Result<Box<dyn tacacsrs_config::source::ConfigObservation>> {
        let receiver = self
            .0
            .lock()
            .await
            .take()
            .expect("the runtime observes once");
        Ok(Box::new(ChangeObservation(receiver)))
    }
}

struct ChangeSource {
    datastore: Arc<ChangeDatastore>,
    client_api: std::path::PathBuf,
}

impl Component for ChangeSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.shared(Arc::new(SourceDatastore(self.datastore)))?;
        composition.shared(Arc::new(CredentialProvider::none()))?;
        composition.shared(Arc::new(client_api_only(&self.client_api)))
    }
}

fn client_api_only(path: &std::path::Path) -> LocalServices {
    LocalServices {
        client_api_endpoint: path.to_str().unwrap().to_owned(),
        ..LocalServices::default()
    }
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets.
async fn a_datastore_change_moves_the_client_api_socket() {
    let directory = std::env::temp_dir().join(format!(
        "tacacsrs-host-client-api-move-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let (first, second) = (directory.join("first.sock"), directory.join("second.sock"));
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let components: Vec<Box<dyn Component>> = vec![
        Box::new(Value::new("runtime policy", PolicyInput::Canonical(RuntimePolicy::default()))),
        Box::new(Value::new("certificate verification", CertificateVerification::Required)),
        Box::new(ChangeSource {
            datastore: Arc::new(ChangeDatastore(tokio::sync::Mutex::new(Some(receiver)))),
            client_api: first.clone(),
        }),
        Box::new(crate::components::ClientApiComponent),
    ];
    let host = bootstrap(components).await.unwrap();
    let config = Arc::new(
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
    let stop = async {
        let connects = |path: std::path::PathBuf| async move {
            tokio::net::UnixStream::connect(path).await.is_ok()
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while !connects(first.clone()).await {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the client API must bind the first socket");
        sender
            .send(tacacsrs_config::source::ConfigChangeEvent::Changed(
                tacacsrs_config::source::ConfigChange {
                    runtime_policy: None,
                    local_services: Some(Arc::new(client_api_only(&second))),
                    delta: tacacsrs_config::source::ConfigDelta::diff(None, &config),
                    config: Arc::clone(&config),
                },
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !(connects(second.clone()).await && !first.exists()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the client API must move to the second socket");
    };
    tokio::time::timeout(Duration::from_secs(10), host.run_until(stop))
        .await
        .unwrap()
        .unwrap();
    assert!(!second.exists(), "shutdown must remove the socket");
    std::fs::remove_dir_all(directory).unwrap();
}
