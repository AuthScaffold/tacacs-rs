//! KubeSONiC source and registration components.

use std::sync::Arc;

use async_trait::async_trait;
use dill::component;

use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_lifecycle::{
    ApplicationReadiness, BoxError, ComponentHealth, HealthCheck, HealthCheckContext,
    HealthCheckResult, HealthGroup, HealthMember, HostedService, ShutdownSignal,
};
use tacacsrs_provider::{CredentialProvider, SourceDatastore};

use crate::credentials::MountedCredentials;
use crate::datastore::KubeSonicConfigDb;
use crate::environment::Environment;
use crate::registration::{
    registration_settings, LoopbackRegistrar, RegistrarSettings, RegistrationReadiness,
    RegistrationStatus,
};

/// Returns the components of the KubeSONiC profile.
///
/// The first component is [`KubeSonicSource`]. When loopback registration is
/// enabled, a [`RegistrationComponent`] follows it. No component does I/O
/// before preparation.
///
/// # Errors
/// Returns an error when the datastore or registration settings are invalid.
pub fn components(input: Environment) -> anyhow::Result<Vec<Box<dyn Component>>> {
    let registration = registration_settings(&input)?;
    let mut components: Vec<Box<dyn Component>> = vec![Box::new(KubeSonicSource::new(input)?)];
    if let Some(settings) = registration {
        components.push(Box::new(RegistrationComponent::new(settings)));
    }
    Ok(components)
}

/// Supplies the ConfigDB datastore, the mounted credentials, and the local
/// services of the environment.
pub struct KubeSonicSource {
    datastore: KubeSonicConfigDb,
    credentials: MountedCredentials,
    local_services: LocalServices,
}

impl KubeSonicSource {
    /// Stable component name.
    pub const NAME: &'static str = "KubeSONiC source";

    /// Creates an inert source from validated environment inputs.
    ///
    /// # Errors
    /// Returns an error when the datastore settings are invalid.
    pub fn new(input: Environment) -> anyhow::Result<Self> {
        Ok(Self {
            datastore: KubeSonicConfigDb::new(input.source)?,
            credentials: MountedCredentials::new(input.credentials),
            local_services: input.local_services,
        })
    }
}

impl Component for KubeSonicSource {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let credentials = Arc::new(self.credentials);
        composition.shared(Arc::new(SourceDatastore(Arc::new(self.datastore))))?;
        composition
            .shared(Arc::new(CredentialProvider::observed(credentials.clone(), credentials)))?;
        composition.shared(Arc::new(self.local_services))
    }
}

/// Adds the loopback registrar, its readiness group, and its health check.
///
/// The registrar waits until each member of [`RegistrationReadiness`] is
/// healthy. This component adds the [`ApplicationReadiness`] of the host to
/// that group. Other components can add more members. The component also adds
/// the [`RegistrationStatus`] of the registrar to the [`ComponentHealth`]
/// group, so the health registry of the host reports it.
pub struct RegistrationComponent {
    settings: RegistrarSettings,
}

impl RegistrationComponent {
    /// Creates the component for validated registrar settings.
    #[must_use]
    pub fn new(settings: RegistrarSettings) -> Self {
        Self { settings }
    }
}

impl Component for RegistrationComponent {
    fn name(&self) -> &'static str {
        RegistrarService::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.shared(Arc::new(RegistrationStatus::default()))?;
        composition.require_group::<RegistrationReadiness>();
        composition.health_member::<RegistrationReadiness, ApplicationReadinessMember, _>(
            <ApplicationReadinessMember as dill::Component>::builder(),
        )?;
        composition.health_member::<ComponentHealth, RegistrationHealth, _>(
            <RegistrationHealth as dill::Component>::builder(),
        )?;
        composition.hosted_service(RegistrarService::builder(self.settings))
    }
}

/// Reports the latest outcome of the loopback registrar.
struct RegistrationHealth(Arc<RegistrationStatus>);

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<ComponentHealth>)]
impl RegistrationHealth {
    fn new(status: Arc<RegistrationStatus>) -> Self {
        Self(status)
    }
}

impl Named for RegistrationHealth {
    const NAME: &'static str = "kubesonic-loopback-registration";
}

#[async_trait]
impl HealthCheck for RegistrationHealth {
    async fn check(&self, _: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
        Ok(self.0.health())
    }
}

impl HealthMember<ComponentHealth> for RegistrationHealth {
    fn name(&self) -> &'static str {
        Self::NAME
    }
}

/// Adds the readiness of the host application to the registration group.
struct ApplicationReadinessMember(Arc<ApplicationReadiness>);

#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HealthMember<RegistrationReadiness>)]
impl ApplicationReadinessMember {
    fn new(readiness: Arc<ApplicationReadiness>) -> Self {
        Self(readiness)
    }
}

impl Named for ApplicationReadinessMember {
    const NAME: &'static str = ApplicationReadiness::NAME;
}

#[async_trait]
impl HealthCheck for ApplicationReadinessMember {
    async fn check(&self, context: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
        self.0.check(context).await
    }
}

impl HealthMember<RegistrationReadiness> for ApplicationReadinessMember {
    fn name(&self) -> &'static str {
        Self::NAME
    }
}

/// Runs the loopback registrar with the members of its readiness group.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct RegistrarService {
    #[component(explicit)]
    settings: RegistrarSettings,
    members: Vec<Arc<dyn HealthMember<RegistrationReadiness>>>,
    status: Arc<RegistrationStatus>,
}

impl Named for RegistrarService {
    const NAME: &'static str = LoopbackRegistrar::NAME;
}

#[async_trait]
impl HostedService for RegistrarService {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        let readiness = HealthGroup::new(self.members.clone())?;
        Arc::new(LoopbackRegistrar::new(self.settings.clone(), readiness, self.status.clone()))
            .run(shutdown)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn disabled_registration_selects_only_the_source() {
        let input = Environment::parse(BTreeMap::new()).unwrap();
        let names: Vec<_> = components(input)
            .unwrap()
            .iter()
            .map(|component| component.name())
            .collect();
        assert_eq!(names, [KubeSonicSource::NAME]);
    }

    #[test]
    fn enabled_registration_adds_the_registrar() {
        let mut input = Environment::parse(BTreeMap::new()).unwrap();
        input.loopback.enabled = true;
        let names: Vec<_> = components(input)
            .unwrap()
            .iter()
            .map(|component| component.name())
            .collect();
        assert_eq!(names, [KubeSonicSource::NAME, LoopbackRegistrar::NAME]);
    }

    #[test]
    fn source_registers_observed_credentials() {
        let input = Environment::parse(BTreeMap::new()).unwrap();
        let mut composition = Composition::default();
        composition.require::<SourceDatastore>();
        composition.require::<CredentialProvider>();
        composition.require::<LocalServices>();
        Box::new(KubeSonicSource::new(input).unwrap())
            .register(&mut composition)
            .unwrap();
        let graph = composition.validate().unwrap();
        let (resolver, changes) = (*graph.one::<CredentialProvider>().unwrap())
            .clone()
            .into_parts();
        assert!(resolver.is_some() && changes.is_some());
    }

    struct Ready;

    #[async_trait]
    impl HealthCheck for Ready {
        async fn check(&self, _: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
            Ok(HealthCheckResult::healthy())
        }
    }

    #[tokio::test]
    async fn registration_reports_its_status_in_the_health_registry() {
        use tacacsrs_lifecycle::{HealthRegistry, HealthStatus};

        let mut input = Environment::parse(BTreeMap::new()).unwrap();
        input.loopback.enabled = true;
        let mut composition = Composition::default();
        composition
            .shared(Arc::new(ApplicationReadiness::new(Ready)))
            .unwrap();
        let settings = registration_settings(&input).unwrap().unwrap();
        Box::new(RegistrationComponent::new(settings))
            .register(&mut composition)
            .unwrap();
        let graph = composition.validate().unwrap();
        let registry = graph.one::<HealthRegistry>().unwrap();
        let entries: Vec<_> = registry
            .check_all()
            .await
            .into_iter()
            .map(|entry| (entry.group, entry.name, entry.status))
            .collect();
        assert_eq!(
            entries,
            [
                (
                    "kubesonic-registration-readiness",
                    "application-readiness",
                    HealthStatus::Healthy
                ),
                ("component", "kubesonic-loopback-registration", HealthStatus::Degraded),
            ]
        );
    }

    #[test]
    fn registration_settings_apply_the_environment_validation() {
        let mut input = Environment::parse(BTreeMap::new()).unwrap();
        input.loopback.enabled = true;
        let settings = registration_settings(&input).unwrap().unwrap();
        assert_eq!(settings.port, 49);
        let invalid: [fn(&mut Environment); 5] = [
            |input| input.local_services.tacacs_proxy_endpoint = None,
            |input| input.local_services.tacacs_proxy_enabled = false,
            |input| input.local_services.tacacs_proxy_endpoint = Some("192.0.2.1:49".into()),
            |input| input.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:0".into()),
            |input| input.loopback.priority = 0,
        ];
        for change in invalid {
            let mut changed = input.clone();
            change(&mut changed);
            assert!(registration_settings(&changed).is_err());
            assert!(components(changed).is_err());
        }
    }
}
