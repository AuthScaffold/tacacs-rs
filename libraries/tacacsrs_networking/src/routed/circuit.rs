//! Per-endpoint operation circuit state.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

#[derive(Debug, Default)]
struct CircuitState {
    revision: u64,
    opened_at: Option<Instant>,
    recovery_trial_active: bool,
}

/// Circuit state shared by callers of one endpoint operation.
#[derive(Debug, Default)]
pub(super) struct OperationCircuit {
    state: Mutex<CircuitState>,
}

impl OperationCircuit {
    pub(super) fn is_open(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .opened_at
            .is_some()
    }

    pub(super) fn open(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.opened_at = Some(Instant::now());
        state.recovery_trial_active = false;
        state.revision = state.revision.wrapping_add(1);
    }

    fn resolve_recovery(&self, revision: u64, succeeded: Option<bool>) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.revision != revision || !state.recovery_trial_active {
            return false;
        }
        match succeeded {
            Some(true) => state.opened_at = None,
            Some(false) => state.opened_at = Some(Instant::now()),
            None => {}
        }
        state.recovery_trial_active = false;
        state.revision = state.revision.wrapping_add(1);
        true
    }

    pub(super) fn try_begin_recovery(
        self: &Arc<Self>,
        recovery_interval: Duration,
    ) -> Option<RecoveryPermit> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let opened_at = state.opened_at?;
        if state.recovery_trial_active || opened_at.elapsed() < recovery_interval {
            return None;
        }
        state.recovery_trial_active = true;
        Some(RecoveryPermit {
            circuit: Arc::clone(self),
            revision: state.revision,
        })
    }
}

/// Lease that limits a half-open circuit to one real recovery request.
pub(super) struct RecoveryPermit {
    circuit: Arc<OperationCircuit>,
    revision: u64,
}

impl RecoveryPermit {
    pub(super) fn succeed(&self) -> bool {
        self.circuit.resolve_recovery(self.revision, Some(true))
    }

    #[cfg(test)]
    pub(super) fn fail(&self) {
        self.circuit.resolve_recovery(self.revision, Some(false));
    }
}

impl Drop for RecoveryPermit {
    fn drop(&mut self) {
        self.circuit.resolve_recovery(self.revision, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stale_success_cannot_close_a_newer_failure() {
        let circuit = Arc::new(OperationCircuit::default());
        circuit.open();
        let stale = circuit.try_begin_recovery(Duration::ZERO).unwrap();
        circuit.open();
        let current = circuit.try_begin_recovery(Duration::ZERO).unwrap();
        stale.succeed();
        assert!(circuit.is_open());
        assert!(circuit.try_begin_recovery(Duration::ZERO).is_none());
        current.succeed();
        assert!(!circuit.is_open());
    }

    #[tokio::test(start_paused = true)]
    async fn stale_failure_or_drop_cannot_release_a_newer_trial() {
        for fail in [false, true] {
            let circuit = Arc::new(OperationCircuit::default());
            circuit.open();
            let stale = circuit.try_begin_recovery(Duration::ZERO).unwrap();
            circuit.open();
            let current = circuit.try_begin_recovery(Duration::ZERO).unwrap();
            if fail {
                stale.fail();
            }
            drop(stale);
            assert!(circuit.try_begin_recovery(Duration::ZERO).is_none());
            current.succeed();
            assert!(!circuit.is_open());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn one_recovery_trial_starts_after_the_interval() {
        let circuit = Arc::new(OperationCircuit::default());
        circuit.open();

        assert!(circuit.try_begin_recovery(Duration::from_secs(5)).is_none());
        tokio::time::advance(Duration::from_secs(5)).await;

        let permit = circuit
            .try_begin_recovery(Duration::from_secs(5))
            .expect("one recovery trial");
        assert!(circuit.try_begin_recovery(Duration::from_secs(5)).is_none());
        permit.succeed();
        assert!(!circuit.is_open());
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_recovery_permit_allows_another_trial() {
        let circuit = Arc::new(OperationCircuit::default());
        circuit.open();
        tokio::time::advance(Duration::from_secs(1)).await;

        drop(
            circuit
                .try_begin_recovery(Duration::from_secs(1))
                .expect("first trial"),
        );
        assert!(circuit.try_begin_recovery(Duration::from_secs(1)).is_some());
    }
}
