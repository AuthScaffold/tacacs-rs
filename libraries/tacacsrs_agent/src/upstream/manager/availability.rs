//! Runtime publication serialized with generation-scoped availability observations.

use std::sync::Mutex;

use crate::runtime::{RuntimeGeneration, RuntimeHealthPublisher, UpstreamAvailability};

/// Identity of one connection attempt in a server-set generation.
#[derive(Debug, Clone, Copy)]
pub(super) struct AvailabilityAttempt {
    generation: u64,
    sequence: u64,
}

#[derive(Debug, Default)]
struct ObservationState {
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
}

impl PublicationController {
    pub(super) fn new(health: RuntimeHealthPublisher) -> Self {
        Self {
            health,
            state: Mutex::new(ObservationState::default()),
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

    /// Serializes catalog publication with availability observations.
    /// The runtime write lock must already be held before this method is called.
    pub(super) fn publish_runtime(
        &self,
        generation: u64,
        server_count: usize,
        configuration_applied: Option<bool>,
        materially_changed: bool,
        publish: impl FnOnce(u64) -> Option<crate::MaterializationRevision>,
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
