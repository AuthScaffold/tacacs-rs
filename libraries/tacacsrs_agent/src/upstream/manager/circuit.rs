//! Per-server operation circuit state.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::time::Instant;

#[derive(Debug, Default)]
struct CircuitState {
    opened_at: Option<Instant>,
    recovery_trial_active: bool,
}

/// Circuit state shared by all local service surfaces for one server operation.
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
    }

    pub(super) fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.opened_at = None;
        state.recovery_trial_active = false;
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
            resolved: AtomicBool::new(false),
        })
    }

    fn abandon_recovery(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.recovery_trial_active = false;
    }
}

/// Lease that limits a half-open circuit to one real recovery request.
pub(super) struct RecoveryPermit {
    circuit: Arc<OperationCircuit>,
    resolved: AtomicBool,
}

impl RecoveryPermit {
    pub(super) fn succeed(&self) {
        if !self.resolved.swap(true, Ordering::AcqRel) {
            self.circuit.close();
        }
    }

    pub(super) fn fail(&self) {
        if !self.resolved.swap(true, Ordering::AcqRel) {
            self.circuit.open();
        }
    }
}

impl Drop for RecoveryPermit {
    fn drop(&mut self) {
        if !self.resolved.swap(true, Ordering::AcqRel) {
            self.circuit.abandon_recovery();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
