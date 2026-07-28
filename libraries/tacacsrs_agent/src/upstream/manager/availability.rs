//! Race-safe aggregate upstream availability observations.

use std::sync::Mutex;

use crate::runtime::{DegradationReason, RuntimeHealthPublisher, UpstreamAvailability};

/// Identity of one aggregate connection attempt within a server-set generation.
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

/// Publishes only observations that still belong to the current server set and
/// are newer than the last completed authoritative attempt.
pub(super) struct AvailabilityTracker {
    health: RuntimeHealthPublisher,
    state: Mutex<ObservationState>,
}

impl AvailabilityTracker {
    pub(super) fn new(health: RuntimeHealthPublisher) -> Self {
        Self {
            health,
            state: Mutex::new(ObservationState::default()),
        }
    }

    pub(super) fn begin_attempt(&self) -> AvailabilityAttempt {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_sequence = state.next_sequence.saturating_add(1);
        AvailabilityAttempt {
            generation: state.generation,
            sequence: state.next_sequence,
        }
    }

    pub(super) fn available(&self, attempt: AvailabilityAttempt) {
        self.observe(attempt, UpstreamAvailability::Available);
    }

    pub(super) fn unavailable(&self, attempt: AvailabilityAttempt) {
        self.observe(attempt, UpstreamAvailability::Unavailable);
    }

    pub(super) fn reset(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = state.generation.saturating_add(1);
        state.next_sequence = 0;
        state.last_observed_sequence = 0;
        self.health
            .set_upstream_availability(UpstreamAvailability::Unknown);
        self.health
            .set_degraded(DegradationReason::UpstreamsUnavailable, false);
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
        self.health.set_degraded(
            DegradationReason::UpstreamsUnavailable,
            availability == UpstreamAvailability::Unavailable,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::EnabledServices;

    use super::*;

    #[test]
    fn newer_success_cannot_be_overwritten_by_older_failure() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let tracker = AvailabilityTracker::new(health.clone());
        let older = tracker.begin_attempt();
        let newer = tracker.begin_attempt();

        tracker.available(newer);
        tracker.unavailable(older);

        assert_eq!(health.snapshot().upstream_availability(), UpstreamAvailability::Available,);
    }

    #[test]
    fn server_set_reset_invalidates_in_flight_attempts() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let tracker = AvailabilityTracker::new(health.clone());
        let old_generation = tracker.begin_attempt();
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
