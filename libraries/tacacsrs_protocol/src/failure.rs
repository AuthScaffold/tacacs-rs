//! Failure facts and the structured [`ServiceError`] returned by the local
//! service.
//!
//! Delivery describes the failed logical operation, not transport connectivity.
//! Unknown delivery never permits automatic replay, including authentication.
//! [`FailureFacts`] records the cause, phase, and delivery state, and
//! [`ServiceError`] pairs those facts with an operator-facing message and the
//! optional server, runtime generation, and attempt number.

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

/// Structured error returned by the local service when a request cannot be
/// fulfilled.
///
/// Direct clients and IPC adapters preserve these facts without flattening them
/// into message text. Replay advice derives from the known cause and delivery
/// state. A temporary transport failure does not make unknown delivery safe.
///
/// # Builder pattern
///
/// ```
/// # use tacacsrs_protocol::failure::{
/// #     DeliveryState, FailureCategory, FailureFacts, FailurePhase, RetryAdvice, ServiceError,
/// # };
/// let facts = FailureFacts::new(
///     FailureCategory::Unavailable,
///     FailurePhase::Routing,
///     DeliveryState::NotSent,
/// );
/// let error = ServiceError::new("connection unavailable before transmission", facts)
///     .with_server("tacacs-a:49");
///
/// assert_eq!(error.message, "connection unavailable before transmission");
/// assert_eq!(error.server.as_deref(), Some("tacacs-a:49"));
/// assert_eq!(error.facts.retry_advice(), RetryAdvice::AfterRecovery);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// Error text suitable for logs and operator-facing diagnostics.
    pub message: String,
    /// Upstream server associated with the error, if the service selected one.
    pub server: Option<String>,
    /// Known cause, phase, and delivery state. Replay advice derives from these facts.
    pub facts: FailureFacts,
    /// Captured routing generation, scoped to the running service instance.
    pub runtime_generation: Option<u64>,
    /// One-based attempt number within the captured request.
    pub attempt: Option<std::num::NonZeroU32>,
}

impl ServiceError {
    /// Creates an error from explicit facts without assuming delivery or retry safety.
    #[must_use]
    pub fn new(message: impl Into<String>, facts: FailureFacts) -> Self {
        Self {
            message: message.into(),
            server: None,
            facts,
            runtime_generation: None,
            attempt: None,
        }
    }

    /// Associates an upstream server name with this error.
    #[must_use]
    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    /// Records the routing generation captured before admission.
    #[must_use]
    pub const fn with_runtime_generation(mut self, generation: u64) -> Self {
        self.runtime_generation = Some(generation);
        self
    }

    /// Records the one-based upstream attempt number.
    #[must_use]
    pub const fn with_attempt(mut self, attempt: std::num::NonZeroU32) -> Self {
        self.attempt = Some(attempt);
        self
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)?;
        if let Some(server) = &self.server {
            write!(formatter, " via {server}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ServiceError {}

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
