//! Rule tests for the composition ledger and graph.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use dill::component;

use tacacsrs_lifecycle::{
    BoxError, EmptyGroup, HealthCheck, HealthCheckContext, HealthCheckResult, HealthGroupKind,
    HealthMember, HealthRegistry, HealthStatus, HostedService, ShutdownSignal,
};

use crate::{check_names, Component, Composition, Named, Value};

#[derive(Default)]
struct FixtureState {
    runs: AtomicUsize,
    constructions: AtomicUsize,
}

struct FixtureGroup;
impl HealthGroupKind for FixtureGroup {
    const NAME: &'static str = "fixture-readiness";
    const EMPTY: EmptyGroup = EmptyGroup::Reject;
}

struct FixtureCheck {
    state: Arc<FixtureState>,
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<FixtureGroup>)]
impl FixtureCheck {
    fn new(state: Arc<FixtureState>) -> Self {
        state.constructions.fetch_add(1, Ordering::AcqRel);
        Self { state }
    }
}

impl Named for FixtureCheck {
    const NAME: &'static str = "fixture-started";
}

#[async_trait]
impl HealthCheck for FixtureCheck {
    async fn check(&self, context: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
        Ok(if self.state.runs.load(Ordering::Acquire) > 0 {
            HealthCheckResult::healthy()
        } else {
            HealthCheckResult::new(context.failure_status())
        })
    }
}

impl HealthMember<FixtureGroup> for FixtureCheck {
    fn name(&self) -> &'static str {
        Self::NAME
    }
}

// Fixtures for composition rule tests. Each role needs a distinct type.

macro_rules! hosted {
    ($type:ident, $name:literal) => {
        impl Named for $type {
            const NAME: &'static str = $name;
        }

        #[async_trait]
        impl HostedService for $type {
            fn name(&self) -> &'static str {
                Self::NAME
            }

            async fn run(self: Arc<Self>, _shutdown: ShutdownSignal) -> anyhow::Result<()> {
                Ok(())
            }
        }
    };
}

struct Missing;

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
#[allow(dead_code)]
struct NeedsMissing {
    missing: Arc<Missing>,
}
hosted!(NeedsMissing, "needs-missing");

trait Greeting: Send + Sync {}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn Greeting)]
struct English;
impl Greeting for English {}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn Greeting)]
struct French;
impl Greeting for French {}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
#[allow(dead_code)]
struct NeedsGreeting {
    greeting: Arc<dyn Greeting>,
}
hosted!(NeedsGreeting, "needs-greeting");

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
#[allow(dead_code)]
struct NeedsOneMember {
    member: Arc<dyn HealthMember<FixtureGroup>>,
}
hosted!(NeedsOneMember, "needs-one-member");

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
#[allow(dead_code)]
struct NeedsOptional {
    value: Option<Arc<English>>,
}
hosted!(NeedsOptional, "needs-optional");

#[component]
#[dill::scope(dill::Singleton)]
#[allow(dead_code)]
struct Left {
    right: Arc<Right>,
}

#[component]
#[dill::scope(dill::Singleton)]
#[allow(dead_code)]
struct Right {
    left: Arc<Left>,
}

struct OptionalGroup;
impl HealthGroupKind for OptionalGroup {
    const NAME: &'static str = "optional";
    const EMPTY: EmptyGroup = EmptyGroup::Allow;
}

static GROUP_CONSUMERS: AtomicUsize = AtomicUsize::new(0);

struct NeedsRequiredGroup;

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
impl NeedsRequiredGroup {
    fn new(members: Vec<Arc<dyn HealthMember<FixtureGroup>>>) -> Self {
        drop(members);
        GROUP_CONSUMERS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}
hosted!(NeedsRequiredGroup, "needs-required-group");

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
#[allow(dead_code)]
struct NeedsOptionalGroup {
    members: Vec<Arc<dyn HealthMember<OptionalGroup>>>,
}
hosted!(NeedsOptionalGroup, "needs-optional-group");

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct First;
hosted!(First, "duplicate");

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct Second;
hosted!(Second, "duplicate");

fn resolve(composition: Composition) -> anyhow::Result<Vec<Arc<dyn HostedService>>> {
    let graph = composition.validate()?;
    let services = graph.hosted_services()?;
    graph.finish()?;
    Ok(services)
}

fn resolve_error(composition: Composition) -> String {
    match resolve(composition) {
        Ok(_) => panic!("Resolution must fail"),
        Err(error) => format!("{error:#}"),
    }
}

#[test]
fn missing_dependency_fails_before_resolution() {
    let mut composition = Composition::default();
    composition
        .hosted_service(<NeedsMissing as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("not valid"));
}

#[test]
fn ambiguous_single_dependency_fails() {
    let mut composition = Composition::default();
    composition
        .provide::<dyn Greeting, _, _>(<English as dill::Component>::builder())
        .unwrap();
    composition
        .provide::<dyn Greeting, _, _>(<French as dill::Component>::builder())
        .unwrap();
    composition
        .hosted_service(<NeedsGreeting as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("2 registrations provide it"));
}

#[test]
fn single_dependency_on_a_collection_role_fails() {
    let state = Arc::new(FixtureState::default());
    let mut composition = Composition::default();
    composition.shared(state).unwrap();
    composition
        .health_member::<FixtureGroup, FixtureCheck, _>(<FixtureCheck as dill::Component>::builder())
        .unwrap();
    composition
        .hosted_service(<NeedsOneMember as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("which no registration allows"));
}

#[test]
fn unrecognized_dependency_form_fails() {
    let mut composition = Composition::default();
    composition
        .dependency(<English as dill::Component>::builder())
        .unwrap();
    composition
        .hosted_service(<NeedsOptional as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("which no registration allows"));
}

#[test]
fn opaque_dependency_override_fails_before_construction() {
    let mut composition = Composition::default();
    composition.shared(Arc::new(Facet("registered"))).unwrap();
    composition
        .hosted_service(
            <NeedsFacet as dill::Component>::builder()
                .with_facet_fn(|_| panic!("An opaque dependency must not run")),
        )
        .unwrap();
    assert!(resolve_error(composition).contains("binds an opaque dependency"));
}

#[test]
fn dependency_cycle_fails() {
    let mut composition = Composition::default();
    composition
        .dependency(<Left as dill::Component>::builder())
        .unwrap();
    composition
        .dependency(<Right as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("dependency cycle"));
}

#[test]
fn empty_required_group_fails_only_with_a_consumer_and_before_its_constructor() {
    let mut composition = Composition::default();
    composition.require_group::<FixtureGroup>();
    composition
        .hosted_service(<NeedsRequiredGroup as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("requires at least one member"));
    assert_eq!(GROUP_CONSUMERS.load(Ordering::Acquire), 0);

    assert!(resolve(Composition::default()).unwrap().is_empty());
}

#[test]
fn empty_optional_group_is_allowed() {
    let mut composition = Composition::default();
    composition.require_group::<OptionalGroup>();
    composition
        .hosted_service(<NeedsOptionalGroup as dill::Component>::builder())
        .unwrap();
    assert_eq!(resolve(composition).unwrap().len(), 1);
}

#[test]
fn duplicate_names_and_types_fail_at_registration() {
    let mut composition = Composition::default();
    composition
        .hosted_service(<First as dill::Component>::builder())
        .unwrap();
    assert!(composition
        .hosted_service(<Second as dill::Component>::builder())
        .is_err());
    assert!(composition
        .dependency(<First as dill::Component>::builder())
        .is_err());
}

#[test]
fn duplicate_component_names_fail() {
    let fixture = || Box::new(Value::new("fixture", ())) as Box<dyn Component>;
    assert!(check_names(&[fixture(), fixture()]).is_err());
}

#[component]
#[dill::interface(dyn HostedService)]
struct Transient;
hosted!(Transient, "transient");

#[test]
fn registration_that_is_not_a_singleton_fails() {
    let mut composition = Composition::default();
    let error = composition
        .hosted_service(<Transient as dill::Component>::builder())
        .unwrap_err();
    assert!(format!("{error:#}").contains("must be singletons"));
}

#[test]
fn group_consumer_without_require_group_fails_before_construction() {
    let mut composition = Composition::default();
    composition
        .shared(Arc::new(FixtureState::default()))
        .unwrap();
    composition
        .health_member::<FixtureGroup, FixtureCheck, _>(<FixtureCheck as dill::Component>::builder())
        .unwrap();
    let consumers = GROUP_CONSUMERS.load(Ordering::Acquire);
    composition
        .hosted_service(<NeedsRequiredGroup as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("which no registration allows"));
    assert_eq!(GROUP_CONSUMERS.load(Ordering::Acquire), consumers);
}

#[test]
fn role_registered_without_its_helper_fails() {
    let mut composition = Composition::default();
    composition
        .dependency(<First as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("is not registered as one"));
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct Drifted;

impl Named for Drifted {
    const NAME: &'static str = "registered";
}

#[async_trait]
impl HostedService for Drifted {
    fn name(&self) -> &'static str {
        "runtime"
    }

    async fn run(self: Arc<Self>, _shutdown: ShutdownSignal) -> anyhow::Result<()> {
        Ok(())
    }
}

#[test]
fn runtime_name_that_differs_from_the_registered_name_fails() {
    let mut composition = Composition::default();
    composition
        .hosted_service(<Drifted as dill::Component>::builder())
        .unwrap();
    assert!(resolve_error(composition).contains("differ from the registered names"));
}


/// A value that the host supplies after validation.
struct Facet(&'static str);

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct NeedsFacet {
    facet: Arc<Facet>,
}
hosted!(NeedsFacet, "needs-facet");

#[component]
#[dill::scope(dill::Singleton)]
#[allow(dead_code)]
struct Input {
    facet: Arc<Facet>,
}

#[test]
fn deferred_value_reaches_its_consumer_after_supply() {
    let mut composition = Composition::default();
    composition.deferred::<Facet>().unwrap();
    composition
        .hosted_service(<NeedsFacet as dill::Component>::builder())
        .unwrap();
    let graph = composition.validate().unwrap();
    let error = graph.hosted_services().err().unwrap();
    assert!(format!("{error:#}").contains("is not supplied"));
    graph.supply(Arc::new(Facet("supplied"))).unwrap();
    assert!(graph.supply(Arc::new(Facet("again"))).is_err());
    assert!(graph.supply(Arc::new(English)).is_err());
    assert_eq!(graph.hosted_services().unwrap().len(), 1);
    assert_eq!(graph.one::<NeedsFacet>().unwrap().facet.0, "supplied");
    graph.finish().unwrap();
}

#[test]
fn host_input_that_needs_a_deferred_value_fails_with_its_name() {
    let mut composition = Composition::default();
    composition.deferred::<Facet>().unwrap();
    composition
        .dependency(<Input as dill::Component>::builder())
        .unwrap();
    let graph = composition.validate().unwrap();
    let error = graph.one::<Input>().err().unwrap();
    assert!(format!("{error:#}").contains("needs the deferred value"));
}

#[test]
fn required_value_needs_exactly_one_provider() {
    let mut composition = Composition::default();
    composition.require::<dyn Greeting>();
    assert!(composition
        .validate()
        .err()
        .is_some_and(|error| format!("{error:#}").contains("0 registrations")));

    let mut composition = Composition::default();
    composition.require::<dyn Greeting>();
    composition
        .provide::<dyn Greeting, _, _>(<English as dill::Component>::builder())
        .unwrap();
    composition
        .provide::<dyn Greeting, _, _>(<French as dill::Component>::builder())
        .unwrap();
    assert!(composition
        .validate()
        .err()
        .is_some_and(|error| format!("{error:#}").contains("2 registrations")));

    let mut composition = Composition::default();
    composition.require::<dyn Greeting>();
    composition
        .provide::<dyn Greeting, _, _>(<English as dill::Component>::builder())
        .unwrap();
    assert!(composition
        .validate()
        .unwrap()
        .one::<dyn Greeting>()
        .is_ok());
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct Third;
hosted!(Third, "third");

#[test]
fn members_keep_their_registration_order() {
    let mut composition = Composition::default();
    composition
        .hosted_service(<Third as dill::Component>::builder())
        .unwrap();
    composition
        .hosted_service(<First as dill::Component>::builder())
        .unwrap();
    let names: Vec<_> = resolve(composition)
        .unwrap()
        .iter()
        .map(|service| service.name())
        .collect();
    assert_eq!(names, ["third", "duplicate"]);
}

#[test]
fn undeclared_role_member_fails() {
    let mut composition = Composition::default();
    let error = composition
        .member::<dyn Greeting, English, _>(<English as dill::Component>::builder())
        .unwrap_err();
    assert!(format!("{error:#}").contains("is not declared"));
}

impl Named for English {
    const NAME: &'static str = "english";
}

#[tokio::test]
async fn value_component_shares_its_value() {
    let mut components: Vec<Box<dyn Component>> = vec![Box::new(Value::new("facet", Facet("v")))];
    crate::prepare_all(&mut components).await.unwrap();
    let mut composition = Composition::default();
    crate::register_all(components, &mut composition).unwrap();
    composition.require::<Facet>();
    let graph = composition.validate().unwrap();
    assert_eq!(graph.one::<Facet>().unwrap().0, "v");
}

macro_rules! health_member {
    ($type:ident, $registered:literal, $runtime:literal) => {
        impl Named for $type {
            const NAME: &'static str = $registered;
        }

        #[async_trait]
        impl HealthCheck for $type {
            async fn check(&self, _: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
                Ok(HealthCheckResult::healthy())
            }
        }

        impl HealthMember<FixtureGroup> for $type {
            fn name(&self) -> &'static str {
                $runtime
            }
        }
    };
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<FixtureGroup>)]
#[allow(dead_code)]
struct DeferredHealth {
    facet: Arc<Facet>,
}
health_member!(DeferredHealth, "deferred", "deferred");

#[test]
fn finish_rejects_pending_health_dependencies_before_constructing_members() {
    let state = Arc::new(FixtureState::default());
    let mut composition = Composition::default();
    composition.shared(state.clone()).unwrap();
    composition.deferred::<Facet>().unwrap();
    composition.require_group::<FixtureGroup>();
    composition
        .health_member::<FixtureGroup, FixtureCheck, _>(<FixtureCheck as dill::Component>::builder())
        .unwrap();
    composition
        .health_member::<FixtureGroup, DeferredHealth, _>(
            <DeferredHealth as dill::Component>::builder(),
        )
        .unwrap();
    let error = composition.validate().unwrap().finish().unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("fixture-readiness needs the deferred value"));
    assert!(message.contains("Facet"));
    assert_eq!(state.constructions.load(Ordering::Acquire), 0);
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<FixtureGroup>)]
struct SwappedFirst;
health_member!(SwappedFirst, "first", "second");

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<FixtureGroup>)]
struct SwappedSecond;
health_member!(SwappedSecond, "second", "first");

#[test]
fn finish_rejects_swapped_health_member_names() {
    let mut composition = Composition::default();
    composition.require_group::<FixtureGroup>();
    composition
        .health_member::<FixtureGroup, SwappedFirst, _>(
            <SwappedFirst as dill::Component>::builder(),
        )
        .unwrap();
    composition
        .health_member::<FixtureGroup, SwappedSecond, _>(
            <SwappedSecond as dill::Component>::builder(),
        )
        .unwrap();
    let error = composition.validate().unwrap().finish().unwrap_err();
    assert!(format!("{error:#}").contains("differ from the registered names"));
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<OptionalGroup>)]
struct OptionalMember;

impl Named for OptionalMember {
    const NAME: &'static str = "optional-member";
}

#[async_trait]
impl HealthCheck for OptionalMember {
    async fn check(&self, _: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
        Ok(HealthCheckResult::degraded().with_description("waits"))
    }
}

impl HealthMember<OptionalGroup> for OptionalMember {
    fn name(&self) -> &'static str {
        Self::NAME
    }
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
#[allow(dead_code)]
struct NeedsRegistry {
    registry: Arc<HealthRegistry>,
}
hosted!(NeedsRegistry, "needs-registry");

#[tokio::test]
async fn registry_reports_every_group_without_a_group_consumer() {
    let state = Arc::new(FixtureState::default());
    let mut composition = Composition::default();
    composition.shared(state.clone()).unwrap();
    composition
        .health_member::<FixtureGroup, FixtureCheck, _>(<FixtureCheck as dill::Component>::builder())
        .unwrap();
    composition
        .health_member::<OptionalGroup, OptionalMember, _>(
            <OptionalMember as dill::Component>::builder(),
        )
        .unwrap();
    composition
        .hosted_service(<NeedsRegistry as dill::Component>::builder())
        .unwrap();
    let graph = composition.validate().unwrap();
    assert_eq!(state.constructions.load(Ordering::Acquire), 0);
    graph.hosted_services().unwrap();
    let registry = graph.one::<HealthRegistry>().unwrap();
    graph.finish().unwrap();
    assert_eq!(state.constructions.load(Ordering::Acquire), 1);

    let entries: Vec<_> = registry
        .check_all()
        .await
        .into_iter()
        .map(|entry| (entry.group, entry.name, entry.status, entry.description))
        .collect();
    assert_eq!(
        entries,
        [
            ("fixture-readiness", "fixture-started", HealthStatus::Unhealthy, None),
            ("optional", "optional-member", HealthStatus::Degraded, Some("waits".to_owned())),
        ]
    );
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<FixtureGroup>)]
#[allow(dead_code)]
struct ReadsRegistry {
    registry: Arc<HealthRegistry>,
}
health_member!(ReadsRegistry, "reads-registry", "reads-registry");

#[test]
fn health_member_that_reads_the_registry_is_a_cycle() {
    let mut composition = Composition::default();
    composition
        .health_member::<FixtureGroup, ReadsRegistry, _>(
            <ReadsRegistry as dill::Component>::builder(),
        )
        .unwrap();
    assert!(resolve_error(composition).contains("dependency cycle"));
}

struct SameName;
impl HealthGroupKind for SameName {
    const NAME: &'static str = "optional";
    const EMPTY: EmptyGroup = EmptyGroup::Allow;
}

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<SameName>)]
struct SameNameMember;

impl Named for SameNameMember {
    const NAME: &'static str = "same-name";
}

#[async_trait]
impl HealthCheck for SameNameMember {
    async fn check(&self, _: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
        Ok(HealthCheckResult::healthy())
    }
}

impl HealthMember<SameName> for SameNameMember {
    fn name(&self) -> &'static str {
        Self::NAME
    }
}

#[test]
fn two_health_groups_with_one_name_fail_at_registration() {
    let mut composition = Composition::default();
    composition
        .health_member::<OptionalGroup, OptionalMember, _>(
            <OptionalMember as dill::Component>::builder(),
        )
        .unwrap();
    let error =
        composition
            .health_member::<SameName, SameNameMember, _>(
                <SameNameMember as dill::Component>::builder(),
            )
            .unwrap_err();
    assert!(format!("{error:#}").contains("More than one health group is named optional"));
}
