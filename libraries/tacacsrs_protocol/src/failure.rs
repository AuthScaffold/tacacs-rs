//! Failure facts shared by direct clients and local IPC adapters.
//!
//! Delivery describes the failed logical operation, not transport connectivity.
//! Unknown delivery never permits automatic replay, including authentication.

/// The known cause of an operation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCategory {
    /// The available error does not establish a more specific cause.
    Unclassified,
    /// The local request is invalid.
    InvalidRequest,
    /// No usable configured endpoint or service is available.
    Unavailable,
    /// The operation exceeds the current capacity limit.
    Overloaded,
    /// The operation exhausted its deadline.
    Deadline,
    /// Upstream transport or exchange execution failed.
    Transport,
    /// A received message violates the protocol contract.
    Protocol,
    /// The caller or host cancelled the operation.
    Cancelled,
    /// An internal service failure prevents completion.
    Internal,
}

/// The boundary at which a failure became known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePhase {
    /// The available error does not establish a phase.
    Unknown,
    /// Local request validation or encoding.
    Validation,
    /// Admission to the bounded operation queue.
    Admission,
    /// Endpoint selection or binding before operation transmission.
    Routing,
    /// Upstream setup, transmission, or reply processing.
    Upstream,
    /// Local IPC connection or RPC execution.
    Ipc,
}

/// Whether the failed operation can have executed remotely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    /// The operation did not reach its upstream transport.
    NotSent,
    /// Remote execution is possible and no valid reply establishes the outcome.
    OutcomeUnknown,
}

/// Advice for a later independent request, not an instruction to replay now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAdvice {
    /// Do not replay this operation automatically.
    Never,
    /// The operation was not sent and a later request can succeed after recovery.
    AfterRecovery,
}

/// Coherent failure facts with replay advice derived from known delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureFacts {
    category: FailureCategory,
    phase: FailurePhase,
    delivery: DeliveryState,
}

impl FailureFacts {
    /// Records known facts without inferring successful delivery from an error.
    #[must_use]
    pub const fn new(
        category: FailureCategory,
        phase: FailurePhase,
        delivery: DeliveryState,
    ) -> Self {
        Self {
            category,
            phase,
            delivery,
        }
    }

    /// Returns the known failure category.
    #[must_use]
    pub const fn category(self) -> FailureCategory {
        self.category
    }

    /// Returns the boundary at which failure became known.
    #[must_use]
    pub const fn phase(self) -> FailurePhase {
        self.phase
    }

    /// Returns the conservative delivery state of the logical operation.
    #[must_use]
    pub const fn delivery(self) -> DeliveryState {
        self.delivery
    }

    /// Returns replay advice without allowing unknown outcomes to become retriable.
    #[must_use]
    pub const fn retry_advice(self) -> RetryAdvice {
        match (self.delivery, self.category) {
            (
                DeliveryState::NotSent,
                FailureCategory::Unavailable
                | FailureCategory::Overloaded
                | FailureCategory::Deadline
                | FailureCategory::Transport,
            ) => RetryAdvice::AfterRecovery,
            _ => RetryAdvice::Never,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_delivery_never_permits_replay() {
        for category in [
            FailureCategory::Unclassified,
            FailureCategory::InvalidRequest,
            FailureCategory::Unavailable,
            FailureCategory::Overloaded,
            FailureCategory::Deadline,
            FailureCategory::Transport,
            FailureCategory::Protocol,
            FailureCategory::Cancelled,
            FailureCategory::Internal,
        ] {
            let facts =
                FailureFacts::new(category, FailurePhase::Upstream, DeliveryState::OutcomeUnknown);
            assert_eq!(facts.retry_advice(), RetryAdvice::Never);
        }
    }

    #[test]
    fn delivery_and_cause_remain_distinct_from_retry_advice() {
        let invalid = FailureFacts::new(
            FailureCategory::InvalidRequest,
            FailurePhase::Validation,
            DeliveryState::NotSent,
        );
        let uncertain = FailureFacts::new(
            FailureCategory::Transport,
            FailurePhase::Upstream,
            DeliveryState::OutcomeUnknown,
        );
        assert_eq!(invalid.retry_advice(), uncertain.retry_advice());
        assert_ne!(invalid.delivery(), uncertain.delivery());
        assert_ne!(invalid.category(), uncertain.category());
        assert_ne!(invalid.phase(), uncertain.phase());

        let unsent = FailureFacts::new(
            FailureCategory::Transport,
            FailurePhase::Upstream,
            DeliveryState::NotSent,
        );
        assert_eq!(unsent.retry_advice(), RetryAdvice::AfterRecovery);
    }
}
