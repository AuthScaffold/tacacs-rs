//! Publication owner for one runtime generation.
//!
//! This module hosts the upstream manager's snapshot-write methods next to the
//! [`PublicationController`], so the whole atomic write path lives in one file.
//!
//! [`PublicationController`] owns the publication state and the final health
//! commit for the upstream manager. It holds the observation and policy-revision
//! state, serializes availability observations, and runs the single atomic
//! health mutation that makes a new runtime generation visible. The adjacent
//! [`UpstreamManager`] owns the active catalog
//! (`active_snapshot`) and prepares each replacement. This controller owns when,
//! and whether, that preparation becomes visible.
//!
//! # Write path
//!
//! One reload travels in one direction through fixed owners:
//!
//! 1. The service validates and prepares the complete catalog outside publication locks.
//! 2. The service and manager acquire their publication locks. The manager checks
//!    current catalog identity, then takes the `active_snapshot` write lock.
//! 3. While the manager holds that write lock, it calls [`publish_runtime`] or
//!    [`publish_policy`] on this controller. The controller takes its own state
//!    lock and commits the runtime generation, server count, and health in one
//!    health mutation.
//! 4. The manager-supplied commit callback runs inside that health mutation. It
//!    swaps `active_snapshot` and runs coordinator bookkeeping. The commit never
//!    awaits and never reacquires the snapshot, state, or health locks.
//!
//! Upstream retirement awaits only after the write lock is released, so a
//! cancelled retirement cannot leave bookkeeping behind the applied snapshot.
//!
//! [`publish_runtime`]: PublicationController::publish_runtime
//! [`publish_policy`]: PublicationController::publish_policy
//!
//! # Lock order
//!
//! Acquire locks only in this order: `active_snapshot` write lock (manager) ->
//! publication state lock (this controller) -> health watch.
//!
//! # Availability observations
//!
//! Each connection attempt takes an [`AvailabilityAttempt`] token scoped to the
//! current availability generation. A materially changed catalog advances that
//! generation and resets the sequence. The controller then ignores a late or
//! stale observation that names a replaced generation or an older sequence.
//!
//! # Policy admission
//!
//! A policy update advances a [`crate::PolicyRevision`] before validation. A
//! stale success or rejection that names an older revision returns
//! [`crate::PolicyUpdate::Superseded`] and does not mutate health.

use std::sync::{Arc, Mutex};

use tacacsrs_config::TacacsPlusServer;
use tacacsrs_networking::routed::EndpointConnector;

use super::server_set::{RuntimeRoutingSnapshot, ServerSet};
use super::prepared_server::PreparedServer;
use super::UpstreamManager;
use crate::config::{PreparedProxyPolicy, RuntimePolicy};
use crate::runtime::{RuntimeGeneration, RuntimeHealthPublisher, UpstreamAvailability};

/// Owns unpublished model payload and commit captures until publication or disposal.
/// Fields drop in declaration order. The preparation lease must remain last.
pub(crate) struct PublicationCandidate<
    Commit,
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    pub(crate) servers: Vec<Arc<TacacsPlusServer>>,
    pub(crate) proxy_downstream_obfuscation: PreparedProxyPolicy,
    pub(crate) validity: Option<crate::runtime::CredentialLifetime>,
    prepared_servers: Vec<Arc<PreparedServer>>,
    catalog: Option<PreparedCatalog<Connector>>,
    commit: Commit,
    pub(crate) preparation: Option<Arc<crate::runtime::candidate_preparation::Preparation>>,
}

struct PreparedCatalog<Connector: EndpointConnector> {
    base: Arc<ServerSet<Connector>>,
    replacement: Arc<ServerSet<Connector>>,
}

struct NativePreparation {
    servers: Vec<Arc<TacacsPlusServer>>,
    prepared_servers: Vec<Arc<PreparedServer>>,
    error: Option<anyhow::Error>,
    #[cfg(test)]
    jobs: Arc<NativeJobs>,
    _lease: Option<tacacsrs_credential_resolution::WorkScope>,
}

#[cfg(test)]
#[derive(Default)]
struct NativeJobs {
    running: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
struct NativeJob(Arc<NativeJobs>);

#[cfg(test)]
impl Drop for NativeJob {
    fn drop(&mut self) {
        self.0
            .running
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl NativePreparation {
    fn run(
        mut self,
        baseline: &[Arc<PreparedServer>],
        options: tacacsrs_config::prepare::PrepareOptions,
        #[cfg(test)] pause: Option<Box<dyn FnOnce() + Send>>,
    ) -> Self {
        #[cfg(test)]
        let _job = {
            let running = self
                .jobs
                .running
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            self.jobs
                .peak
                .fetch_max(running, std::sync::atomic::Ordering::SeqCst);
            NativeJob(self.jobs.clone())
        };
        #[cfg(test)]
        if let Some(pause) = pause {
            pause();
        }
        for server in self.servers.drain(..) {
            let reusable = baseline
                .iter()
                .find(|state| state.server.as_ref() == server.as_ref())
                .cloned();
            let slot = match reusable {
                Some(slot) => Ok(slot),
                None => PreparedServer::new(server, options.clone()).map(Arc::new),
            };
            match slot {
                Ok(slot) => self.prepared_servers.push(slot),
                Err(error) => {
                    self.error = Some(error);
                    break;
                }
            }
        }
        self
    }
}

impl<Commit, Connector: EndpointConnector> PublicationCandidate<Commit, Connector> {
    pub(crate) fn new(
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        validity: Option<crate::runtime::CredentialLifetime>,
        preparation: Option<Arc<crate::runtime::candidate_preparation::Preparation>>,
        commit: Commit,
    ) -> Self {
        Self {
            servers,
            proxy_downstream_obfuscation,
            validity,
            prepared_servers: Vec::new(),
            catalog: None,
            commit,
            preparation,
        }
    }

    pub(crate) fn with_commit<Next>(self, commit: Next) -> PublicationCandidate<Next, Connector> {
        PublicationCandidate {
            servers: self.servers,
            proxy_downstream_obfuscation: self.proxy_downstream_obfuscation,
            validity: self.validity,
            prepared_servers: self.prepared_servers,
            catalog: self.catalog,
            commit,
            preparation: self.preparation,
        }
    }
}

/// Identity of one connection attempt in a server-set generation.
#[derive(Debug, Clone, Copy)]
pub(super) struct AvailabilityAttempt {
    generation: u64,
    sequence: u64,
}

#[derive(Debug, Default)]
struct ObservationState {
    policy_revision: crate::PolicyRevision,
    generation: u64,
    next_sequence: u64,
    last_observed_sequence: u64,
}

/// Commits runtime health and accepts observations only for the current server set.
///
/// An observation must also be newer than the last authoritative attempt.
pub(super) struct PublicationController {
    health: RuntimeHealthPublisher,
    state: Mutex<ObservationState>,
    /// Test-only hook that pauses one publication between its atomic health
    /// commit and upstream retirement. The owning module arms it and the reload
    /// path awaits it.
    #[cfg(test)]
    publication_pause: Mutex<Option<std::sync::Arc<tokio::sync::Notify>>>,
    #[cfg(test)]
    native_preparation_pause: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    prepared_client_pause: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    #[cfg(test)]
    native_jobs: Arc<NativeJobs>,
}

impl PublicationController {
    pub(super) fn admit_policy(&self) -> crate::PolicyRevision {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.policy_revision.advance();
        state.policy_revision
    }

    pub(super) fn reject_policy(&self, revision: crate::PolicyRevision) -> crate::PolicyUpdate {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if revision != state.policy_revision {
            return crate::PolicyUpdate::Superseded;
        }
        self.health
            .set_degraded(crate::DegradationReason::CandidatePolicyRejected, true);
        crate::PolicyUpdate::Rejected(revision)
    }

    /// Commits a policy update if its revision is still current.
    ///
    /// The caller must already hold the `active_snapshot` write lock. The
    /// `publish` callback swaps the snapshot inside the atomic health mutation
    /// and must not await or reacquire these locks. A stale revision returns
    /// [`crate::PolicyUpdate::Superseded`] without mutating health.
    pub(super) fn publish_policy(
        &self,
        revision: crate::PolicyRevision,
        generation: u64,
        publish: impl FnOnce(),
    ) -> crate::PolicyUpdate {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if revision != state.policy_revision {
            return crate::PolicyUpdate::Superseded;
        }
        self.health
            .publish_policy(RuntimeGeneration::new(generation), revision, publish);
        crate::PolicyUpdate::Applied(revision)
    }

    pub(super) fn new(health: RuntimeHealthPublisher) -> Self {
        Self {
            health,
            state: Mutex::new(ObservationState::default()),
            #[cfg(test)]
            publication_pause: Mutex::new(None),
            #[cfg(test)]
            native_preparation_pause: Mutex::new(None),
            #[cfg(test)]
            prepared_client_pause: Mutex::new(None),
            #[cfg(test)]
            native_jobs: Arc::new(NativeJobs::default()),
        }
    }

    /// Arms a one-shot pause for the next publication. The reload path awaits the
    /// returned notify after the atomic commit and before upstream retirement.
    #[cfg(test)]
    pub(super) fn pause_next_publication(&self) -> std::sync::Arc<tokio::sync::Notify> {
        let pause = std::sync::Arc::new(tokio::sync::Notify::new());
        *self.publication_pause.lock().unwrap() = Some(pause.clone());
        pause
    }

    /// Awaits an armed publication pause, if any. This runs after the write lock
    /// is released, so it never holds the snapshot or health locks.
    #[cfg(test)]
    pub(super) async fn wait_for_publication_pause(&self) {
        let pause = self.publication_pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.notified().await;
        }
    }

    #[cfg(test)]
    fn pause_native_preparation(&self) -> (Arc<tokio::sync::Notify>, std::sync::mpsc::Sender<()>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let (release, barrier) = std::sync::mpsc::channel();
        *self.native_preparation_pause.lock().unwrap() = Some(Box::new(move || {
            signal.notify_one();
            barrier.recv().unwrap();
        }));
        (entered, release)
    }

    #[cfg(test)]
    fn take_native_preparation_pause(&self) -> Option<Box<dyn FnOnce() + Send>> {
        self.native_preparation_pause.lock().unwrap().take()
    }

    #[cfg(test)]
    pub(super) fn pause_prepared_client(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        *self.prepared_client_pause.lock().unwrap() = Some((entered.clone(), release.clone()));
        (entered, release)
    }

    #[cfg(test)]
    async fn wait_for_prepared_client_pause(&self) {
        let pause = self.prepared_client_pause.lock().unwrap().take();
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
    }

    pub(super) fn begin_attempt(&self, generation: u64) -> AvailabilityAttempt {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_sequence = state.next_sequence.saturating_add(1);
        AvailabilityAttempt {
            generation,
            sequence: state.next_sequence,
        }
    }

    pub(super) fn available(&self, attempt: AvailabilityAttempt) {
        self.observe(attempt, UpstreamAvailability::Available);
    }

    pub(super) fn unavailable(&self, attempt: AvailabilityAttempt) {
        self.observe(attempt, UpstreamAvailability::Unavailable);
    }

    #[cfg(test)]
    pub(super) fn reset(&self) -> u64 {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = state.generation.saturating_add(1);
        state.next_sequence = 0;
        state.last_observed_sequence = 0;
        self.health
            .set_upstream_availability(UpstreamAvailability::Unknown);
        state.generation
    }

    /// Commits one runtime generation with its availability observations.
    ///
    /// The caller must already hold the `active_snapshot` write lock. A
    /// materially changed catalog advances the availability generation and
    /// resets the observation sequence. The `publish` callback receives that
    /// availability generation, swaps the snapshot, and runs coordinator
    /// bookkeeping inside the atomic health mutation. It must not await or
    /// reacquire these locks.
    pub(super) fn publish_runtime(
        &self,
        generation: u64,
        server_count: usize,
        configuration_applied: Option<bool>,
        materially_changed: bool,
        publish: impl FnOnce(u64) -> Option<crate::runtime::MaterializationCommit>,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if materially_changed {
            state.generation = state.generation.saturating_add(1);
            state.next_sequence = 0;
            state.last_observed_sequence = 0;
        }
        self.health.publish_runtime(
            RuntimeGeneration::new(generation),
            server_count,
            configuration_applied,
            materially_changed,
            || publish(state.generation),
        );
    }

    fn observe(&self, attempt: AvailabilityAttempt, availability: UpstreamAvailability) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if attempt.generation != state.generation {
            return;
        }
        if attempt.sequence <= state.last_observed_sequence {
            return;
        }

        state.last_observed_sequence = attempt.sequence;
        self.health.set_upstream_availability(availability);
    }
}

/// Snapshot-write methods for the [`UpstreamManager`]. They are co-located with
/// the [`PublicationController`] so the whole atomic write path stays in one
/// file. Each takes the `active_snapshot` write lock and commits through the
/// controller in one health mutation.
impl<Connector: EndpointConnector> UpstreamManager<Connector> {
    #[cfg(test)]
    pub(crate) fn native_preparation_counts(&self) -> (usize, usize) {
        (
            self.publication
                .native_jobs
                .running
                .load(std::sync::atomic::Ordering::SeqCst),
            self.publication
                .native_jobs
                .peak
                .load(std::sync::atomic::Ordering::SeqCst),
        )
    }
    #[cfg(test)]
    pub(crate) fn pause_client_preparation(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        self.publication.pause_prepared_client()
    }
    #[cfg(test)]
    pub(crate) fn pause_native_preparation(
        &self,
    ) -> (Arc<tokio::sync::Notify>, std::sync::mpsc::Sender<()>) {
        self.publication.pause_native_preparation()
    }

    pub(crate) fn publish_policy(
        &self,
        revision: crate::PolicyRevision,
        runtime_policy: RuntimePolicy,
    ) -> anyhow::Result<crate::PolicyUpdate> {
        let mut current = self
            .active_snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_open()?;
        let generation = current.generation.wrapping_add(1);
        Ok(self.publication.publish_policy(revision, generation, || {
            current.admission.update(&runtime_policy);
            *current = Arc::new(RuntimeRoutingSnapshot {
                generation,
                availability_generation: current.availability_generation,
                server_set: Arc::clone(&current.server_set),
                proxy_downstream_obfuscation: current.proxy_downstream_obfuscation.clone(),
                admission: Arc::clone(&current.admission),
                runtime_policy: Arc::new(runtime_policy),
                credential_lifetime: current.credential_lifetime,
            });
        }))
    }

    pub(crate) fn publish_initial_health(&self, applied: bool) {
        let current = self
            .active_snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.publication.publish_runtime(
            current.generation,
            current.server_set.server_count(),
            Some(applied),
            false,
            |_| None,
        );
    }

    pub(crate) async fn prepare_candidate<Commit: Send>(
        &self,
        mut candidate: PublicationCandidate<Commit, Connector>,
    ) -> anyhow::Result<PublicationCandidate<Commit, Connector>> {
        if candidate.catalog.is_some() {
            return Ok(candidate);
        }
        self.ensure_open()?;
        let previous = self.current_server_set();
        if let Some(preparation) = &candidate.preparation {
            for server in &candidate.servers {
                if let Some(slot) = previous
                    .servers
                    .iter()
                    .find(|slot| slot.server.as_ref() == server.as_ref())
                {
                    preparation.with_ledger(|ledger| {
                        ledger.reserve_logical(slot.endpoint.prepared().retained_payload_bytes())
                    })?;
                }
            }
        }
        let worker = NativePreparation {
            servers: candidate.servers.clone(),
            prepared_servers: Vec::with_capacity(candidate.servers.len()),
            error: None,
            #[cfg(test)]
            jobs: self.publication.native_jobs.clone(),
            _lease: match candidate.preparation.as_ref() {
                Some(preparation) => Some(
                    preparation
                        .scope
                        .register()
                        .ok_or_else(|| anyhow::anyhow!("candidate work registration is sealed"))?,
                ),
                None => None,
            },
        };
        let baseline = previous.clone();
        let options = match candidate.preparation.as_ref() {
            Some(preparation) => self
                .connect_options
                .clone()
                .with_payload_ledger(preparation.payload_ledger()),
            None => self.connect_options.clone(),
        };
        #[cfg(test)]
        let pause = self.publication.take_native_preparation_pause();
        let requires_native = worker.servers.iter().any(|server| {
            (server.client_identity.is_some() || server.server_authentication.is_some())
                && !baseline
                    .servers
                    .iter()
                    .any(|slot| slot.server.as_ref() == server.as_ref())
        });
        #[cfg(test)]
        let requires_native = requires_native || pause.is_some();
        let prepare = move || {
            worker.run(
                &baseline.servers,
                options,
                #[cfg(test)]
                pause,
            )
        };
        let mut worker = if requires_native {
            let preparing = tokio::task::spawn_blocking(prepare);
            if let Some(preparation) = candidate.preparation.as_ref() {
                preparation.admission.run(preparing).await??
            } else {
                preparing.await?
            }
        } else {
            prepare()
        };
        if let Some(error) = worker.error.take() {
            return Err(error);
        }
        candidate.prepared_servers = std::mem::take(&mut worker.prepared_servers);
        drop(worker);
        let validity = candidate.prepared_servers.iter().try_fold(
            candidate
                .validity
                .unwrap_or(crate::runtime::CredentialLifetime::unbounded()),
            |lifetime, server| lifetime.intersect(server.evidence_lifetime),
        )?;

        let preparing_client = previous.client.with_endpoints(
            candidate
                .prepared_servers
                .iter()
                .map(|server| server.endpoint.clone())
                .collect(),
        );
        #[cfg(test)]
        let preparing_client = async {
            self.publication.wait_for_prepared_client_pause().await;
            preparing_client.await
        };
        let client = if let Some(preparation) = candidate.preparation.as_ref() {
            preparation.admission.run(preparing_client).await?
        } else {
            preparing_client.await
        };
        let new_set = Arc::new(ServerSet {
            servers: std::mem::take(&mut candidate.prepared_servers),
            client,
        });
        candidate.validity = Some(validity);
        candidate.catalog = Some(PreparedCatalog {
            base: previous,
            replacement: new_set,
        });
        Ok(candidate)
    }

    pub(crate) async fn reload_shared_servers_with_retirement(
        &self,
        candidate: PublicationCandidate<
            impl FnOnce() -> Option<crate::runtime::MaterializationCommit> + Send,
            Connector,
        >,
        retirement: Option<tacacsrs_networking::RequestDeadline>,
    ) -> anyhow::Result<()> {
        let mut candidate = self.prepare_candidate(candidate).await?;
        let _reload = if let Some(preparation) = candidate.preparation.as_ref() {
            preparation
                .admission
                .run(self.catalog_reload_lock.lock())
                .await?
        } else {
            self.catalog_reload_lock.lock().await
        };
        let retirement_deadline = retirement.unwrap_or(self.retirement_deadline()?);
        let catalog = candidate
            .catalog
            .take()
            .ok_or_else(|| anyhow::anyhow!("prepared catalog is missing"))?;
        let previous = self.current_server_set();
        anyhow::ensure!(
            Arc::ptr_eq(&previous, &catalog.base),
            "catalog changed during preparation"
        );
        let new_set = catalog.replacement;
        let materially_changed = previous.server_count() != new_set.server_count()
            || previous
                .servers
                .iter()
                .zip(&new_set.servers)
                .any(|(old, new)| !Arc::ptr_eq(old, new));
        let validity = candidate
            .validity
            .unwrap_or(crate::runtime::CredentialLifetime::unbounded());
        let mut urgent = previous.changed_revocation_servers(&new_set);
        {
            let mut history = self
                .prepared_history
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            history.retain(|(endpoint, _)| previous.client.retains_endpoint(endpoint));
            for new in &new_set.servers {
                if history.iter().any(|(_, old)| {
                    old.name == new.server.name
                        && super::server_set::revocation_changed(old, &new.server)
                }) {
                    urgent.insert(new.server.name.as_str());
                }
            }
        }

        {
            let mut current = self
                .active_snapshot
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            anyhow::ensure!(
                !self.closed.load(std::sync::atomic::Ordering::Acquire),
                "The TACACS+ service closed during preparation"
            );
            anyhow::ensure!(validity.is_valid(), "Credential validity expired before publication");
            if let Some(preparation) = candidate.preparation.as_ref() {
                preparation.final_check(current.runtime_policy.candidate_limits())?;
            }
            let generation = current.generation.wrapping_add(1);
            previous.retire_replaced_until(&new_set, retirement_deadline, &urgent);
            self.publication.publish_runtime(
                generation,
                new_set.server_count(),
                Some(true),
                materially_changed,
                |availability_generation| {
                    {
                        let mut history = self
                            .prepared_history
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        for server in &new_set.servers {
                            if !history
                                .iter()
                                .any(|(endpoint, _)| endpoint.same_identity(&server.endpoint))
                            {
                                history.push((server.endpoint.clone(), server.server.clone()));
                            }
                        }
                    }
                    *current = Arc::new(RuntimeRoutingSnapshot {
                        generation,
                        availability_generation,
                        server_set: Arc::clone(&new_set),
                        proxy_downstream_obfuscation: candidate.proxy_downstream_obfuscation,
                        admission: Arc::clone(&current.admission),
                        runtime_policy: Arc::clone(&current.runtime_policy),
                        credential_lifetime: validity,
                    });
                    let mut materialization = (candidate.commit)();
                    if let Some(commit) = &mut materialization {
                        if commit.expired == crate::runtime::ExpiredMaterial::None {
                            commit.validity = validity;
                        }
                    }
                    materialization
                },
            );
        }

        drop(candidate.preparation);
        if new_set.server_count() == 0 {
            log::warn!("Reloaded an empty TACACS+ server set; waiting for configuration");
        } else {
            log::info!("Reloaded the TACACS+ server set: {} server(s)", new_set.server_count());
        }

        #[cfg(test)]
        self.publication.wait_for_publication_pause().await;
        previous.client.retire_replaced(&new_set.client).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::EnabledServices;
    use crate::DegradationReason;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_native_success_and_rejection_own_payload_before_work_lease() {
        use std::future::Future;
        use std::task::{Context, Wake, Waker};
        use crate::runtime::candidate_preparation::CandidateAdmission;

        struct Ready(Arc<tokio::sync::Notify>);
        impl Wake for Ready {
            fn wake(self: Arc<Self>) {
                self.0.notify_one();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.notify_one();
            }
        }
        struct Release(Option<std::sync::mpsc::Sender<()>>);
        impl Drop for Release {
            fn drop(&mut self) {
                if let Some(release) = self.0.take() {
                    let _ = release.send(());
                }
            }
        }

        for reject in [false, true] {
            let slot = Arc::new(tokio::sync::Semaphore::new(1));
            let preparation =
                CandidateAdmission::new(crate::config::RuntimeCandidateLimits::default())
                    .unwrap()
                    .acquire(&slot)
                    .await
                    .unwrap();
            let ledger = preparation.ledger.clone();
            let observer = preparation.scope.register().unwrap();
            let server = Arc::new(
                tacacsrs_config::TacacsPlusServerBuilder::new(
                    "queued",
                    tacacsrs_config::TacacsPlusServerType::all(),
                    "127.0.0.1",
                    49,
                )
                .with_tls13_epsk_psk_only("client", vec![7; 16])
                .build(),
            );
            let weak = Arc::downgrade(&server);
            let mut servers = vec![server];
            if reject {
                servers.push(Arc::new(
                    tacacsrs_config::TacacsPlusServerBuilder::new(
                        "rejected",
                        tacacsrs_config::TacacsPlusServerType::all(),
                        "127.0.0.1",
                        49,
                    )
                    .with_tls13_epsk_psk_only("client", vec![7; 1])
                    .build(),
                ));
            }
            let worker = NativePreparation {
                servers,
                prepared_servers: Vec::new(),
                error: None,
                jobs: Arc::new(NativeJobs::default()),
                _lease: preparation.scope.register(),
            };
            let options = tacacsrs_config::prepare::PrepareOptions::default()
                .with_payload_ledger(preparation.payload_ledger());
            let (release, barrier) = std::sync::mpsc::channel();
            let release = Release(Some(release));
            let ready = Arc::new(tokio::sync::Notify::new());
            let mut handle = Box::pin(tokio::task::spawn_blocking(move || {
                worker.run(
                    &[],
                    options,
                    Some(Box::new(move || {
                        let _ = barrier.recv();
                    })),
                )
            }));
            let waker = Waker::from(Arc::new(Ready(ready.clone())));
            assert!(handle
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending());
            drop(preparation);
            assert!(observer.register().is_none());
            drop(observer);
            assert_eq!(slot.available_permits(), 0);
            drop(release);
            tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
                .await
                .unwrap();
            assert!(handle.is_finished());
            assert!(weak.upgrade().is_some());
            assert!(ledger.lock().unwrap().charges().1 > 0);
            assert_eq!(slot.available_permits(), 0);
            if reject {
                let result = handle.await.unwrap();
                assert!(result.error.is_some());
                assert_eq!(slot.available_permits(), 0);
                drop(result);
            } else {
                drop(handle);
            }
            let permit = tokio::time::timeout(std::time::Duration::from_secs(2), slot.acquire())
                .await
                .unwrap()
                .unwrap();
            assert!(weak.upgrade().is_none());
            assert_eq!(ledger.lock().unwrap().charges().1, 0);
            drop(permit);
        }
    }

    #[test]
    fn replacement_serializes_old_observations_and_publishes_coherent_health() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let tracker = Arc::new(PublicationController::new(health.clone()));
        let old = tracker.begin_attempt(0);
        tracker.unavailable(old);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let committed = Arc::new(AtomicBool::new(false));
        let publishing = {
            let tracker = tracker.clone();
            let entered = entered.clone();
            let release = release.clone();
            let committed = committed.clone();
            std::thread::spawn(move || {
                tracker.publish_runtime(7, 3, Some(true), true, |_| {
                    entered.wait();
                    release.wait();
                    committed.store(true, Ordering::Release);
                    None
                });
            })
        };
        entered.wait();
        let stale = std::thread::spawn(move || tracker.available(old));
        let observed = {
            std::thread::spawn(move || {
                let snapshot = health.snapshot();
                assert!(committed.load(Ordering::Acquire));
                assert_eq!(snapshot.runtime_generation(), Some(RuntimeGeneration::new(7)));
                assert_eq!(snapshot.eligible_server_count(), 3);
                assert!(snapshot.has_applied_configuration());
                assert_eq!(snapshot.upstream_availability(), UpstreamAvailability::Unknown);
                assert!(!snapshot
                    .degradation_reasons()
                    .contains(&DegradationReason::UpstreamsUnavailable));
            })
        };
        release.wait();
        publishing.join().unwrap();
        stale.join().unwrap();
        observed.join().unwrap();
    }

    #[test]
    fn policy_decisions_reject_stale_success_and_failure_without_mutation() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let controller = PublicationController::new(health.clone());
        let older = controller.admit_policy();
        let newer = controller.admit_policy();
        assert_eq!(controller.publish_policy(newer, 1, || {}), crate::PolicyUpdate::Applied(newer));
        let published = health.snapshot();
        assert_eq!(controller.reject_policy(older), crate::PolicyUpdate::Superseded);
        assert_eq!(
            controller.publish_policy(older, 2, || panic!("stale commit must not run")),
            crate::PolicyUpdate::Superseded
        );
        assert_eq!(health.snapshot(), published);
    }

    #[test]
    fn policy_commit_publishes_revision_generation_and_recovery_together() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let controller = Arc::new(PublicationController::new(health.clone()));
        let rejected = controller.admit_policy();
        controller.reject_policy(rejected);
        let revision = controller.admit_policy();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let committed = Arc::new(AtomicBool::new(false));
        let publishing = {
            let entered = entered.clone();
            let release = release.clone();
            let committed = committed.clone();
            std::thread::spawn(move || {
                controller.publish_policy(revision, 8, || {
                    entered.wait();
                    release.wait();
                    committed.store(true, Ordering::Release);
                })
            })
        };
        entered.wait();
        let reading = std::thread::spawn(move || {
            let snapshot = health.snapshot();
            assert!(committed.load(Ordering::Acquire));
            assert_eq!(snapshot.applied_policy_revision(), Some(revision));
            assert_eq!(snapshot.runtime_generation().unwrap().value(), 8);
            assert!(!snapshot
                .degradation_reasons()
                .contains(&DegradationReason::CandidatePolicyRejected));
        });
        release.wait();
        assert_eq!(publishing.join().unwrap(), crate::PolicyUpdate::Applied(revision));
        reading.join().unwrap();
    }

    #[test]
    fn newer_success_cannot_be_overwritten_by_older_failure() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let tracker = PublicationController::new(health.clone());
        let older = tracker.begin_attempt(0);
        let newer = tracker.begin_attempt(0);

        tracker.available(newer);
        tracker.unavailable(older);

        assert_eq!(health.snapshot().upstream_availability(), UpstreamAvailability::Available,);
    }

    #[test]
    fn server_set_reset_invalidates_in_flight_attempts() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let tracker = PublicationController::new(health.clone());
        let old_generation = tracker.begin_attempt(0);
        tracker.unavailable(old_generation);

        tracker.reset();
        tracker.available(old_generation);

        assert_eq!(health.snapshot().upstream_availability(), UpstreamAvailability::Unknown,);
        assert!(!health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::UpstreamsUnavailable));
    }
}
