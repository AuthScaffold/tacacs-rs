//! Desired-source credential materialization and known-good publication state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tokio::sync::Mutex;

use tacacsrs_config::{TacacsPlus, TacacsPlusServer, ValidationOptions, enumerate_server};
use tacacsrs_config::prepare::{
    MaterializationError, MaterializedServer, materialize_servers, resolution_plan,
};
use tacacsrs_credential_resolution::{
    CredentialChangeScope, CredentialKind, CredentialReference, CredentialResolver,
};

use crate::{PreparedProxyPolicy, TacacsClientService};
use super::{
    ExpiredMaterial, MaterialExpiry, MaterializationCommit, MaterializationRevision, SourceRevision,
};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct DependencyKey {
    kind: CredentialKind,
    reference: CredentialReference,
}

struct CoordinatorState {
    desired_source: Option<Arc<TacacsPlus>>,
    desired_runtime_source: Option<Arc<TacacsPlus>>,
    desired_proxy_policy: Option<PreparedProxyPolicy>,
    desired_dependencies: Option<BTreeMap<DependencyKey, BTreeSet<String>>>,
    active_servers: Vec<Arc<TacacsPlusServer>>,
    active_lifetimes: BTreeMap<String, super::CredentialLifetime>,
    revision: MaterializationRevision,
    active_revision: Option<MaterializationRevision>,
    withdrawn_revision: Option<MaterializationRevision>,
    source_current: bool,
    expired: ExpiredMaterial,
    active_credential_references: bool,
}

impl Default for CoordinatorState {
    fn default() -> Self {
        Self {
            desired_source: None,
            desired_runtime_source: None,
            desired_proxy_policy: None,
            desired_dependencies: Some(BTreeMap::new()),
            active_servers: Vec::new(),
            active_lifetimes: BTreeMap::new(),
            revision: MaterializationRevision::default(),
            active_revision: None,
            withdrawn_revision: None,
            source_current: false,
            expired: ExpiredMaterial::None,
            active_credential_references: false,
        }
    }
}

pub(crate) struct MaterializationCoordinator {
    state: Mutex<CoordinatorState>,
    resolver: Option<Arc<dyn CredentialResolver>>,
    validation_options: ValidationOptions,
}

#[derive(Clone)]
pub(crate) struct MaterializationAttempt {
    revision: MaterializationRevision,
    source_update: bool,
    runtime_source: Arc<TacacsPlus>,
    proxy_policy: PreparedProxyPolicy,
    selected_servers: BTreeSet<String>,
}

pub(crate) struct PreparedMaterialization {
    attempt: MaterializationAttempt,
    candidates: Vec<(MaterializedServer, super::CredentialLifetime)>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum PublicationOutcome {
    Published,
    Superseded,
}

impl MaterializationCoordinator {
    pub(crate) fn new(
        resolver: Arc<dyn CredentialResolver>,
        validation_options: ValidationOptions,
    ) -> Self {
        Self {
            state: Mutex::new(CoordinatorState::default()),
            resolver: Some(resolver),
            validation_options,
        }
    }

    pub(crate) fn without_resolver(validation_options: ValidationOptions) -> Self {
        Self {
            state: Mutex::new(CoordinatorState::default()),
            resolver: None,
            validation_options,
        }
    }

    pub(crate) fn has_resolver(&self) -> bool {
        self.resolver.is_some()
    }

    pub(crate) async fn admit_source(&self, source: TacacsPlus) -> SourceRevision {
        let mut state = self.state.lock().await;
        state.revision.source.advance();
        state.desired_source = Some(Arc::new(source));
        state.desired_runtime_source = None;
        state.desired_proxy_policy = None;
        state.desired_dependencies = None;
        state.source_current = true;
        state.revision.source
    }

    pub(crate) async fn reject_source(
        &self,
        revision: SourceRevision,
        health: &crate::RuntimeHealthPublisher,
    ) -> bool {
        let mut state = self.state.lock().await;
        if state.revision.source != revision {
            return false;
        }
        state.desired_runtime_source = None;
        state.desired_proxy_policy = None;
        state.desired_dependencies = None;
        state.source_current = false;
        health.reject_source_candidate();
        true
    }

    pub(crate) async fn reject_observation(&self, health: &crate::RuntimeHealthPublisher) {
        let mut state = self.state.lock().await;
        state.revision.source.advance();
        state.source_current = false;
        state.desired_runtime_source = None;
        state.desired_proxy_policy = None;
        state.desired_dependencies = None;
        health.reject_source_candidate();
    }

    pub(crate) async fn source_unavailable(
        &self,
        health: &crate::RuntimeHealthPublisher,
        disconnected: bool,
    ) {
        let mut state = self.state.lock().await;
        state.source_current = false;
        health.source_unavailable(disconnected);
    }

    #[cfg(test)]
    pub(crate) async fn accept_source(
        &self,
        desired_source: TacacsPlus,
        runtime_source: TacacsPlus,
        proxy_policy: PreparedProxyPolicy,
    ) -> MaterializationAttempt {
        let revision = self.admit_source(desired_source).await;
        self.accept_filtered_source(revision, runtime_source, proxy_policy)
            .await
            .expect("test source must remain current")
    }

    pub(crate) async fn accept_filtered_source(
        &self,
        revision: SourceRevision,
        runtime_source: TacacsPlus,
        proxy_policy: PreparedProxyPolicy,
    ) -> Option<MaterializationAttempt> {
        let dependencies = dependency_index(&runtime_source);
        let runtime_source = Arc::new(runtime_source);
        let selected_servers = runtime_source
            .server
            .iter()
            .map(|server| server.name.clone())
            .collect();
        let mut state = self.state.lock().await;
        if state.revision.source != revision {
            return None;
        }
        state.desired_runtime_source = Some(Arc::clone(&runtime_source));
        state.desired_proxy_policy = Some(proxy_policy.clone());
        state.desired_dependencies = dependencies;
        Some(MaterializationAttempt {
            revision: state.revision,
            source_update: true,
            runtime_source,
            proxy_policy,
            selected_servers,
        })
    }

    #[cfg(test)]
    pub(crate) async fn credential_change(
        &self,
        scope: &CredentialChangeScope,
    ) -> Option<MaterializationAttempt> {
        self.observe_credentials(scope, None).await
    }

    pub(crate) async fn observe_credentials(
        &self,
        scope: &CredentialChangeScope,
        health: Option<&crate::RuntimeHealthPublisher>,
    ) -> Option<MaterializationAttempt> {
        self.begin_credential_update(scope, health, false).await
    }

    pub(crate) async fn refresh_credentials(&self) -> Option<MaterializationAttempt> {
        self.begin_credential_update(&CredentialChangeScope::Unknown, None, true)
            .await
    }

    async fn begin_credential_update(
        &self,
        scope: &CredentialChangeScope,
        health: Option<&crate::RuntimeHealthPublisher>,
        scheduled: bool,
    ) -> Option<MaterializationAttempt> {
        let mut state = self.state.lock().await;
        if scheduled
            && (self.resolver.is_none()
                || state
                    .desired_dependencies
                    .as_ref()
                    .is_none_or(BTreeMap::is_empty)
                || state.expired.contains(MaterialExpiry::Source))
        {
            return None;
        }
        let Some(runtime_source) = state.desired_runtime_source.clone() else {
            if state.desired_source.is_some() {
                state.revision.credentials.advance();
                if state.active_credential_references {
                    if let Some(health) = health {
                        health.set_degraded(crate::DegradationReason::CredentialsStale, true);
                    }
                }
            }
            return None;
        };
        let proxy_policy = state.desired_proxy_policy.clone()?;
        let selected_servers = if state.active_revision == Some(state.revision) {
            match (scope, state.desired_dependencies.as_ref()) {
                (CredentialChangeScope::Known { kind, reference }, Some(dependencies)) => {
                    dependencies
                        .get(&DependencyKey {
                            kind: *kind,
                            reference: reference.clone(),
                        })
                        .cloned()
                        .unwrap_or_default()
                }
                _ => all_server_names(&runtime_source),
            }
        } else {
            all_server_names(&runtime_source)
        };
        if selected_servers.is_empty() {
            return None;
        }
        state.revision.credentials.advance();
        if state.active_credential_references {
            if let Some(health) = health {
                health.set_degraded(crate::DegradationReason::CredentialsStale, true);
            }
        }
        Some(MaterializationAttempt {
            revision: state.revision,
            source_update: false,
            runtime_source,
            proxy_policy,
            selected_servers,
        })
    }

    pub(crate) async fn materialize(
        &self,
        attempt: MaterializationAttempt,
    ) -> anyhow::Result<PreparedMaterialization> {
        let servers = attempt
            .selected_servers
            .iter()
            .map(|server_name| enumerate_server(&attempt.runtime_source, server_name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MaterializationError::enumeration())?;
        let candidates = match self.resolver.as_deref() {
            Some(resolver) => {
                materialize_servers(servers, resolver, &self.validation_options).await?
            }
            None => servers
                .into_iter()
                .map(MaterializedServer::unbounded)
                .collect(),
        };
        let candidates = candidates
            .into_iter()
            .map(|server| {
                let lifetime = super::CredentialLifetime::new(server.validity())?;
                Ok((server, lifetime))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(PreparedMaterialization {
            attempt,
            candidates,
        })
    }

    #[cfg(test)]
    pub(crate) async fn is_current_attempt(&self, attempt: &MaterializationAttempt) -> bool {
        let state = self.state.lock().await;
        attempt.revision == state.revision
    }

    pub(crate) async fn report_credential_result(
        &self,
        attempt: &MaterializationAttempt,
        health: &crate::RuntimeHealthPublisher,
        failed: bool,
    ) -> bool {
        let state = self.state.lock().await;
        if attempt.revision != state.revision {
            return false;
        }
        if failed {
            health
                .reject_materialization(attempt.source_update, state.active_credential_references);
        }
        true
    }

    pub(crate) async fn credentials_unavailable(&self, health: &crate::RuntimeHealthPublisher) {
        let state = self.state.lock().await;
        health.credential_notifications_unavailable(state.active_credential_references);
    }

    pub(crate) async fn publish(
        &self,
        prepared: PreparedMaterialization,
        service: &TacacsClientService,
    ) -> anyhow::Result<PublicationOutcome> {
        let mut state = self.state.lock().await;
        if prepared.attempt.revision != state.revision {
            return Ok(PublicationOutcome::Superseded);
        }
        if state.expired.contains(MaterialExpiry::Source) && !state.source_current {
            return Ok(PublicationOutcome::Superseded);
        }

        let candidate_by_name = prepared
            .candidates
            .into_iter()
            .map(|(server, lifetime)| (server.name.clone(), (server, lifetime)))
            .collect::<BTreeMap<_, _>>();
        let active_by_name = state
            .active_servers
            .iter()
            .map(|server| (server.name.as_str(), Arc::clone(server)))
            .collect::<BTreeMap<_, _>>();
        let mut next_active = Vec::with_capacity(prepared.attempt.runtime_source.server.len());
        let mut next_lifetimes = BTreeMap::new();
        let mut validity = super::CredentialLifetime::unbounded();
        for desired in &prepared.attempt.runtime_source.server {
            let mut lifetime = candidate_by_name
                .get(&desired.name)
                .map(|(_, lifetime)| *lifetime)
                .or_else(|| state.active_lifetimes.get(&desired.name).copied())
                .ok_or_else(|| anyhow::anyhow!("active credential validity is missing"))?;
            if let Some(previous) = state.active_lifetimes.get(&desired.name) {
                if previous.validity == lifetime.validity {
                    lifetime = previous.intersect(lifetime)?;
                }
            }
            validity = validity.intersect(lifetime)?;
            next_lifetimes.insert(desired.name.clone(), lifetime);
            let server = if let Some((candidate, _)) = candidate_by_name.get(&desired.name) {
                active_by_name
                    .get(desired.name.as_str())
                    .filter(|active| active.as_ref() == candidate.server())
                    .cloned()
                    .unwrap_or_else(|| Arc::new(candidate.server().clone()))
            } else {
                active_by_name
                    .get(desired.name.as_str())
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("active server transaction is incomplete"))?
            };
            next_active.push(server);
        }

        service
            .publish_materialized_servers(
                next_active.clone(),
                prepared.attempt.proxy_policy,
                validity,
                move || {
                    state.active_servers = next_active;
                    state.active_lifetimes = next_lifetimes;
                    state.active_revision = Some(state.revision);
                    state.withdrawn_revision = None;
                    state.expired = ExpiredMaterial::None;
                    state.active_credential_references = state
                        .desired_dependencies
                        .as_ref()
                        .is_none_or(|dependencies| !dependencies.is_empty());
                    Some(MaterializationCommit {
                        revision: state.revision,
                        source_current: state.source_current,
                        expired: ExpiredMaterial::None,
                        credential_references: state.active_credential_references,
                        validity,
                    })
                },
            )
            .await?;
        Ok(PublicationOutcome::Published)
    }

    #[cfg(test)]
    pub(crate) async fn expire_source(
        &self,
        expected: MaterializationRevision,
        service: &TacacsClientService,
        health: &crate::RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        self.expire_material(MaterialExpiry::Source, expected, service, health)
            .await
    }

    pub(crate) async fn expire_material(
        &self,
        kind: MaterialExpiry,
        expected: MaterializationRevision,
        service: &TacacsClientService,
        health: &crate::RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        let snapshot = health.snapshot();
        let validity = snapshot
            .credential_lifetime()
            .unwrap_or(super::CredentialLifetime::unbounded());
        let should_expire = match kind {
            MaterialExpiry::Source => {
                snapshot.datastore() != crate::DatastoreState::Current
                    && !state.expired.contains(MaterialExpiry::Source)
            }
            MaterialExpiry::Credentials => {
                !state.expired.contains(MaterialExpiry::Credentials)
                    && (!validity.is_valid()
                        || snapshot
                            .degradation_reasons()
                            .contains(&crate::DegradationReason::CredentialsStale))
            }
        };
        if state.active_revision.or(state.withdrawn_revision) != Some(expected) || !should_expire {
            return Ok(());
        }
        service
            .withdraw_expired_material(move || {
                state.active_servers.clear();
                state.active_lifetimes.clear();
                state.active_revision = None;
                state.withdrawn_revision = Some(expected);
                state.expired = state.expired.with(kind);
                if matches!(kind, MaterialExpiry::Credentials) {
                    state.revision.credentials.advance();
                }
                Some(MaterializationCommit {
                    revision: expected,
                    source_current: state.source_current,
                    expired: state.expired,
                    credential_references: state.active_credential_references,
                    validity,
                })
            })
            .await
    }

    #[cfg(test)]
    pub(crate) async fn active_servers(&self) -> Vec<Arc<TacacsPlusServer>> {
        self.state.lock().await.active_servers.clone()
    }
}

fn all_server_names(source: &TacacsPlus) -> BTreeSet<String> {
    source
        .server
        .iter()
        .map(|server| server.name.clone())
        .collect()
}

fn dependency_index(source: &TacacsPlus) -> Option<BTreeMap<DependencyKey, BTreeSet<String>>> {
    let mut dependencies = BTreeMap::<DependencyKey, BTreeSet<String>>::new();
    for source_server in &source.server {
        let server = enumerate_server(source, &source_server.name).ok()?;
        let plan = resolution_plan(&server).ok()?;
        for request in plan.requests() {
            dependencies
                .entry(DependencyKey {
                    kind: request.kind(),
                    reference: request.reference().clone(),
                })
                .or_default()
                .insert(source_server.name.clone());
        }
    }
    Some(dependencies)
}

#[cfg(test)]
impl MaterializationAttempt {
    fn selected_server_names(&self) -> &BTreeSet<String> {
        &self.selected_servers
    }
}

#[cfg(test)]
mod tests;
