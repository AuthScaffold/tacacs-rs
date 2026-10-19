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
//! 1. The service holds its reload-publication lock, so only one publication
//!    runs end to end. It validates and prepares the inputs.
//! 2. The manager holds its `catalog_reload_lock`, prepares the new server set,
//!    then takes the `active_snapshot` write lock.
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
    fn wait_for_native_preparation_pause(&self) {
        let pause = self.native_preparation_pause.lock().unwrap().take();
        if let Some(pause) = pause {
            pause();
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

    pub(crate) async fn reload_shared_servers_with_retirement(
        &self,
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        retirement: Option<tacacsrs_networking::RequestDeadline>,
        validity: Option<crate::runtime::CredentialLifetime>,
        preparation: Option<Arc<crate::runtime::candidate_preparation::Preparation>>,
        commit: impl FnOnce() -> Option<crate::runtime::MaterializationCommit> + Send,
    ) -> anyhow::Result<()> {
        let _reload = if let Some(preparation) = preparation.as_ref() {
            preparation
                .admission
                .run(self.catalog_reload_lock.lock())
                .await?
        } else {
            self.catalog_reload_lock.lock().await
        };
        anyhow::ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "The TACACS+ service is closed"
        );
        let retirement_deadline = retirement.unwrap_or(self.retirement_deadline()?);
        let previous = self.current_server_set();
        let materially_changed = previous.server_count() != servers.len()
            || previous
                .servers
                .iter()
                .zip(&servers)
                .any(|(old, new)| old.server.as_ref() != new.as_ref());
        let mut new_server_slots = Vec::with_capacity(servers.len());
        #[cfg(test)]
        self.publication.wait_for_native_preparation_pause();
        for server in servers {
            let reusable = previous
                .servers
                .iter()
                .find(|state| state.server.as_ref() == server.as_ref())
                .cloned();
            let slot = match reusable {
                Some(slot) => slot,
                None => Arc::new(PreparedServer::new(server, self.connect_options)?),
            };
            new_server_slots.push(slot);
        }

        let validity = new_server_slots.iter().try_fold(
            validity.unwrap_or(crate::runtime::CredentialLifetime::unbounded()),
            |lifetime, server| lifetime.intersect(server.evidence_lifetime),
        )?;

        let preparing_client = previous.client.with_endpoints(
            new_server_slots
                .iter()
                .map(|server| server.endpoint.clone())
                .collect(),
        );
        let client = if let Some(preparation) = preparation.as_ref() {
            preparation.admission.run(preparing_client).await?
        } else {
            preparing_client.await
        };
        let new_set = Arc::new(ServerSet {
            servers: new_server_slots,
            client,
        });
        let urgent = previous.changed_revocation_servers(&new_set);

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
            if let Some(preparation) = preparation.as_ref() {
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
                    *current = Arc::new(RuntimeRoutingSnapshot {
                        generation,
                        availability_generation,
                        server_set: Arc::clone(&new_set),
                        proxy_downstream_obfuscation,
                        admission: Arc::clone(&current.admission),
                        runtime_policy: Arc::clone(&current.runtime_policy),
                        credential_lifetime: validity,
                    });
                    let mut materialization = commit();
                    if let Some(commit) = &mut materialization {
                        if commit.expired == crate::runtime::ExpiredMaterial::None {
                            commit.validity = validity;
                        }
                    }
                    materialization
                },
            );
        }

        drop(preparation);
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
