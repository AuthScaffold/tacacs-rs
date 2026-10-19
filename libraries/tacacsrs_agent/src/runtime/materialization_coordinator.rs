//! Desired-source credential materialization and known-good publication state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore};
use async_trait::async_trait;

use tacacsrs_config::{TacacsPlus, TacacsPlusServer, ValidationOptions, enumerate_server};
use tacacsrs_config::prepare::{
    MaterializationError, MaterializedServer, materialize_planned_servers, resolution_plan,
    enumerated_payload_bytes, server_payload_bytes, source_payload_bytes,
};
use tacacsrs_credential_resolution::{
    CredentialChangeScope, CredentialKind, CredentialReference, CredentialResolver,
};

use crate::{PreparedProxyPolicy, TacacsClientService};
use super::{
    ExpiredMaterial, MaterialExpiry, MaterializationCommit, MaterializationRevision, SourceRevision,
};
use super::candidate_preparation::{CandidateAdmission, Preparation};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct DependencyKey {
    kind: CredentialKind,
    reference: CredentialReference,
}

#[derive(Clone)]
enum SelectionTrigger {
    All,
    Dependency(DependencyKey),
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
    source_admission: Option<CandidateAdmission>,
    pending_refresh: bool,
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
            source_admission: None,
            pending_refresh: false,
        }
    }
}

pub(crate) struct MaterializationCoordinator {
    state: Mutex<CoordinatorState>,
    resolver: Option<Arc<dyn CredentialResolver>>,
    validation_options: ValidationOptions,
    preparation_slot: Arc<Semaphore>,
    revision_updates: tokio::sync::watch::Sender<MaterializationRevision>,
    #[cfg(test)]
    waiters: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    peak_waiters: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    waiters_changed: tokio::sync::Notify,
}

#[derive(Clone)]
pub(crate) struct MaterializationAttempt {
    revision: MaterializationRevision,
    source_update: bool,
    selection: SelectionTrigger,
    #[cfg(test)]
    selected_servers: BTreeSet<String>,
    admission: CandidateAdmission,
}

pub(crate) struct PreparedMaterialization {
    attempt: MaterializationAttempt,
    candidates: Vec<(MaterializedServer, super::CredentialLifetime)>,
    runtime_source: Arc<TacacsPlus>,
    proxy_policy: PreparedProxyPolicy,
    preparation: Arc<Preparation>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum PublicationOutcome {
    Published,
    Superseded,
}

struct CandidateResolver<'candidate> {
    coordinator: &'candidate MaterializationCoordinator,
    attempt: &'candidate MaterializationAttempt,
    preparation: &'candidate Preparation,
    resolver: &'candidate dyn CredentialResolver,
}

#[async_trait]
impl CredentialResolver for CandidateResolver<'_> {
    async fn resolve(
        &self,
        request: &tacacsrs_credential_resolution::CredentialRequest,
        scope: &tacacsrs_credential_resolution::WorkScope,
    ) -> Result<
        tacacsrs_credential_resolution::ResolvedCredential,
        tacacsrs_credential_resolution::ResolutionError,
    > {
        use tacacsrs_credential_resolution::{ProviderErrorKind, ResolutionError};
        let rejected =
            || ResolutionError::provider(ProviderErrorKind::InvalidMaterial, request.context());
        self.coordinator
            .check_attempt(self.attempt)
            .await
            .map_err(|_| rejected())?;
        self.preparation
            .with_ledger(|ledger| ledger.attempt_request())
            .map_err(|_| rejected())?;
        let credential = self
            .coordinator
            .run_attempt(self.attempt, self.resolver.resolve(request, scope))
            .await
            .map_err(|_| rejected())??;
        self.coordinator
            .check_attempt(self.attempt)
            .await
            .map_err(|_| rejected())?;
        let bytes = credential.payload_bytes().ok_or_else(rejected)?;
        self.preparation
            .with_ledger(|ledger| ledger.reserve_logical(bytes))
            .map_err(|_| rejected())?;
        Ok(credential)
    }
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
            preparation_slot: Arc::new(Semaphore::new(1)),
            revision_updates: tokio::sync::watch::channel(MaterializationRevision::default()).0,
            #[cfg(test)]
            waiters: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            peak_waiters: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            waiters_changed: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn without_resolver(validation_options: ValidationOptions) -> Self {
        Self {
            state: Mutex::new(CoordinatorState::default()),
            resolver: None,
            validation_options,
            preparation_slot: Arc::new(Semaphore::new(1)),
            revision_updates: tokio::sync::watch::channel(MaterializationRevision::default()).0,
            #[cfg(test)]
            waiters: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            peak_waiters: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            waiters_changed: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn has_resolver(&self) -> bool {
        self.resolver.is_some()
    }

    #[cfg(test)]
    pub(crate) async fn admit_source(&self, source: TacacsPlus) -> SourceRevision {
        self.admit_source_at(
            Arc::new(source),
            CandidateAdmission::new(crate::config::RuntimeCandidateLimits::default())
                .expect("generated candidate timeout fits the clock"),
        )
        .await
    }

    pub(crate) async fn admit_source_at(
        &self,
        source: Arc<TacacsPlus>,
        admission: CandidateAdmission,
    ) -> SourceRevision {
        let mut state = self.state.lock().await;
        state.revision.source.advance();
        state.desired_source = Some(source);
        state.source_admission = Some(admission);
        state.pending_refresh = false;
        state.desired_runtime_source = None;
        state.desired_proxy_policy = None;
        state.desired_dependencies = None;
        state.source_current = true;
        self.revision_updates.send_replace(state.revision);
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
        self.revision_updates.send_replace(state.revision);
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
        let runtime_source = Arc::new(runtime_source);
        #[cfg(test)]
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
        state.desired_dependencies = None;
        Some(MaterializationAttempt {
            revision: state.revision,
            source_update: true,
            selection: SelectionTrigger::All,
            #[cfg(test)]
            selected_servers,
            admission: state.source_admission?,
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
        let admission =
            CandidateAdmission::new(crate::config::RuntimeCandidateLimits::default()).ok()?;
        let mut state = self.state.lock().await;
        if scheduled
            && (self.resolver.is_none()
                || state
                    .desired_dependencies
                    .as_ref()
                    .is_some_and(BTreeMap::is_empty)
                || state.expired.contains(MaterialExpiry::Source))
        {
            return None;
        }
        let Some(runtime_source) = state.desired_runtime_source.clone() else {
            if state.desired_source.is_some() {
                if scheduled && state.pending_refresh {
                    return None;
                }
                if scheduled {
                    state.pending_refresh = true;
                }
                state.revision.credentials.advance();
                self.revision_updates.send_replace(state.revision);
                if state.active_credential_references {
                    if let Some(health) = health {
                        health.set_degraded(crate::DegradationReason::CredentialsStale, true);
                    }
                }
            }
            return None;
        };
        state.desired_proxy_policy.as_ref()?;
        let selection = if state.active_revision == Some(state.revision) {
            match (scope, state.desired_dependencies.as_ref()) {
                (CredentialChangeScope::Known { kind, reference }, Some(dependencies)) => {
                    let key = DependencyKey {
                        kind: *kind,
                        reference: reference.clone(),
                    };
                    if !dependencies
                        .get(&key)
                        .is_some_and(|names| !names.is_empty())
                    {
                        return None;
                    }
                    SelectionTrigger::Dependency(key)
                }
                _ => SelectionTrigger::All,
            }
        } else {
            SelectionTrigger::All
        };
        if runtime_source.server.is_empty() {
            return None;
        }
        #[cfg(test)]
        let selected_servers =
            selected_server_names(&selection, &runtime_source, state.desired_dependencies.as_ref());
        state.revision.credentials.advance();
        self.revision_updates.send_replace(state.revision);
        if state.active_credential_references {
            if let Some(health) = health {
                health.set_degraded(crate::DegradationReason::CredentialsStale, true);
            }
        }
        Some(MaterializationAttempt {
            revision: state.revision,
            source_update: false,
            selection,
            #[cfg(test)]
            selected_servers,
            admission,
        })
    }

    #[cfg(test)]
    pub(crate) async fn materialize(
        &self,
        attempt: MaterializationAttempt,
    ) -> anyhow::Result<PreparedMaterialization> {
        let preparation = self.acquire_preparation(attempt.admission).await?;
        self.materialize_in(attempt, preparation).await
    }

    #[cfg(test)]
    async fn materialize_with_request_limit(
        &self,
        mut attempt: MaterializationAttempt,
        limit: u64,
    ) -> anyhow::Result<PreparedMaterialization> {
        attempt.admission.limits.requests = limit;
        self.materialize(attempt).await
    }

    pub(crate) async fn acquire_preparation(
        &self,
        admission: CandidateAdmission,
    ) -> anyhow::Result<Arc<Preparation>> {
        #[cfg(test)]
        let _waiting = {
            let count = self
                .waiters
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            self.peak_waiters
                .fetch_max(count, std::sync::atomic::Ordering::SeqCst);
            self.waiters_changed.notify_one();
            Waiting(&self.waiters)
        };
        admission.acquire(&self.preparation_slot).await
    }

    #[cfg(test)]
    pub(crate) fn preparation_counts(&self) -> (usize, usize, usize) {
        use std::sync::atomic::Ordering;
        (
            1 - self.preparation_slot.available_permits(),
            self.waiters.load(Ordering::SeqCst),
            self.peak_waiters.load(Ordering::SeqCst),
        )
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_preparation_waiters(&self, minimum: usize) {
        loop {
            let changed = self.waiters_changed.notified();
            if self.preparation_counts().1 >= minimum {
                return;
            }
            changed.await;
        }
    }

    pub(crate) async fn current_source(
        &self,
        revision: SourceRevision,
        admission: CandidateAdmission,
    ) -> anyhow::Result<bool> {
        let state = admission.run(self.state.lock()).await?;
        Ok(state.revision.source == revision)
    }

    pub(crate) async fn run_source<Output>(
        &self,
        revision: SourceRevision,
        admission: CandidateAdmission,
        future: impl std::future::Future<Output = Output>,
    ) -> anyhow::Result<Output> {
        let mut changes = self.revision_updates.subscribe();
        anyhow::ensure!(
            self.current_source(revision, admission).await?,
            "candidate preparation was superseded"
        );
        tokio::select! {
            biased;
            _ = changes.wait_for(|current| current.source() != revision) => anyhow::bail!("candidate preparation was superseded"),
            result = admission.run(future) => result,
        }
    }

    async fn run_attempt<Output>(
        &self,
        attempt: &MaterializationAttempt,
        future: impl std::future::Future<Output = Output>,
    ) -> anyhow::Result<Output> {
        let mut changes = self.revision_updates.subscribe();
        self.check_attempt(attempt).await?;
        tokio::select! {
            biased;
            _ = changes.wait_for(|current| *current != attempt.revision) => anyhow::bail!("candidate preparation was superseded"),
            result = attempt.admission.run(future) => result,
        }
    }

    async fn check_attempt(&self, attempt: &MaterializationAttempt) -> anyhow::Result<()> {
        let state = attempt.admission.run(self.state.lock()).await?;
        anyhow::ensure!(
            state.revision == attempt.revision
                && !(state.expired.contains(MaterialExpiry::Source) && !state.source_current),
            "candidate preparation was superseded"
        );
        Ok(())
    }

    // Unrelated short state-lock holders must not reject; publish rechecks expiry under the lock.
    fn installation_current(&self, attempt: &MaterializationAttempt) -> bool {
        attempt.admission.check().is_ok() && *self.revision_updates.borrow() == attempt.revision
    }

    pub(crate) async fn materialize_in(
        &self,
        attempt: MaterializationAttempt,
        preparation: Arc<Preparation>,
    ) -> anyhow::Result<PreparedMaterialization> {
        self.check_attempt(&attempt).await?;
        let (runtime_source, proxy_policy, active_servers, selected_servers) = {
            let state = attempt.admission.run(self.state.lock()).await?;
            (
                state
                    .desired_runtime_source
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("candidate source is missing"))?,
                state
                    .desired_proxy_policy
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("candidate proxy policy is missing"))?,
                state.active_servers.clone(),
                selected_server_names(
                    &attempt.selection,
                    state
                        .desired_runtime_source
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("candidate source is missing"))?,
                    state.desired_dependencies.as_ref(),
                ),
            )
        };
        let mut logical = u64::try_from(
            proxy_policy
                .shared_secret()?
                .map_or(0, |secret| secret.expose_secret().len()),
        )?;
        for server in &runtime_source.server {
            let bytes = if selected_servers.contains(&server.name) {
                enumerated_payload_bytes(&runtime_source, server)?
            } else {
                server_payload_bytes(
                    active_servers
                        .iter()
                        .find(|active| active.name == server.name)
                        .ok_or_else(|| {
                            anyhow::anyhow!("active server transaction is incomplete")
                        })?,
                )?
            };
            logical = logical
                .checked_add(bytes)
                .ok_or_else(|| anyhow::anyhow!("candidate payload size overflow"))?;
        }
        preparation.with_ledger(|ledger| {
            ledger.retain_extra(source_payload_bytes(&runtime_source)?)?;
            ledger.reserve_logical(logical)
        })?;
        let servers = runtime_source
            .server
            .iter()
            .filter(|server| selected_servers.contains(&server.name))
            .map(|server| enumerate_server(&runtime_source, &server.name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MaterializationError::enumeration())?;
        let plans = servers
            .iter()
            .map(resolution_plan)
            .collect::<Result<Vec<_>, _>>()?;
        let requests = plans.iter().try_fold(0_u64, |total, plan| {
            total
                .checked_add(u64::try_from(plan.neutral_plan().requests().len())?)
                .ok_or_else(|| anyhow::anyhow!("candidate request count overflow"))
        })?;
        preparation.with_ledger(|ledger| ledger.plan_requests(requests))?;
        let mut dependencies = BTreeMap::<DependencyKey, BTreeSet<String>>::new();
        for plan in &plans {
            for request in plan.neutral_plan().requests() {
                dependencies
                    .entry(DependencyKey {
                        kind: request.kind(),
                        reference: request.reference().clone(),
                    })
                    .or_default()
                    .insert(request.context().server_name().to_owned());
            }
        }
        {
            let mut state = attempt.admission.run(self.state.lock()).await?;
            anyhow::ensure!(
                state.revision == attempt.revision,
                "candidate preparation was superseded"
            );
            let index = state.desired_dependencies.get_or_insert_with(BTreeMap::new);
            for names in index.values_mut() {
                names.retain(|name| !selected_servers.contains(name));
            }
            for (key, names) in dependencies {
                index.entry(key).or_default().extend(names);
            }
        }
        let candidates = match self.resolver.as_deref() {
            Some(resolver) => {
                let resolver = CandidateResolver {
                    coordinator: self,
                    attempt: &attempt,
                    preparation: &preparation,
                    resolver,
                };
                let check_installation = || self.installation_current(&attempt);
                attempt
                    .admission
                    .run(materialize_planned_servers(
                        servers.into_iter().zip(plans).collect(),
                        &resolver,
                        &preparation.scope,
                        &self.validation_options,
                        &check_installation,
                    ))
                    .await??
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
            runtime_source,
            proxy_policy,
            preparation,
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
        if attempt.revision != state.revision
            || (state.expired.contains(MaterialExpiry::Source) && !state.source_current)
        {
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
        let mut state = prepared.attempt.admission.run(self.state.lock()).await?;
        if prepared.attempt.revision != state.revision {
            return Ok(PublicationOutcome::Superseded);
        }
        if state.expired.contains(MaterialExpiry::Source) && !state.source_current {
            return Ok(PublicationOutcome::Superseded);
        }

        let mut candidate_by_name = prepared
            .candidates
            .into_iter()
            .map(|(server, lifetime)| (server.name.clone(), (server, lifetime)))
            .collect::<BTreeMap<_, _>>();
        let active_by_name = state
            .active_servers
            .iter()
            .map(|server| (server.name.as_str(), Arc::clone(server)))
            .collect::<BTreeMap<_, _>>();
        let mut next_active = Vec::with_capacity(prepared.runtime_source.server.len());
        let mut next_lifetimes = BTreeMap::new();
        let mut validity = super::CredentialLifetime::unbounded();
        for desired in &prepared.runtime_source.server {
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
            let server = if let Some((candidate, _)) = candidate_by_name.remove(&desired.name) {
                active_by_name
                    .get(desired.name.as_str())
                    .filter(|active| active.as_ref() == candidate.server())
                    .cloned()
                    .unwrap_or_else(|| Arc::new(candidate.into_parts().0))
            } else {
                active_by_name
                    .get(desired.name.as_str())
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("active server transaction is incomplete"))?
            };
            next_active.push(server);
        }
        drop(candidate_by_name);
        drop(prepared.runtime_source);

        service
            .publish_materialized_servers(
                next_active.clone(),
                prepared.proxy_policy,
                validity,
                prepared.preparation,
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
                    self.revision_updates.send_replace(state.revision);
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

    #[cfg(test)]
    pub(crate) async fn hold_state(&self) -> impl Drop + '_ {
        self.state.lock().await
    }
}

fn all_server_names(source: &TacacsPlus) -> BTreeSet<String> {
    source
        .server
        .iter()
        .map(|server| server.name.clone())
        .collect()
}

fn selected_server_names(
    selection: &SelectionTrigger,
    source: &TacacsPlus,
    dependencies: Option<&BTreeMap<DependencyKey, BTreeSet<String>>>,
) -> BTreeSet<String> {
    match selection {
        SelectionTrigger::All => all_server_names(source),
        SelectionTrigger::Dependency(key) => dependencies
            .and_then(|index| index.get(key))
            .cloned()
            .unwrap_or_default(),
    }
}

#[cfg(test)]
struct Waiting<'waiter>(&'waiter std::sync::atomic::AtomicUsize);

#[cfg(test)]
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl MaterializationAttempt {
    pub(crate) fn admission(&self) -> CandidateAdmission {
        self.admission
    }

    pub(crate) fn with_admission(mut self, admission: CandidateAdmission) -> Self {
        self.admission = admission;
        self
    }

    #[cfg(test)]
    fn selected_server_names(&self) -> &BTreeSet<String> {
        &self.selected_servers
    }
}

#[cfg(test)]
mod tests;
