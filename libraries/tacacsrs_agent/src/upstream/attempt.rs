//! Classified upstream request failures used by replay policy.

use tacacsrs_networking::{FixedExchangeError, TransmissionState};
use tacacsrs_protocol::failure::{DeliveryState, FailureCategory, FailureFacts, FailurePhase};
use tacacsrs_protocol::failure::ServiceError;

/// Conservative transmission state for one upstream request attempt.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum AttemptFailureKind {
    /// Local request preparation failed before server selection could matter.
    InvalidRequest,
    /// The request did not reach a transport.
    NotSent,
    /// The request can have reached the server without a valid reply.
    OutcomeUnknown,
}

/// Upstream request error with replay-relevant transmission state.
#[derive(Debug)]
pub(crate) struct UpstreamRequestError {
    kind: AttemptFailureKind,
    category: Option<FailureCategory>,
    source: anyhow::Error,
}

impl UpstreamRequestError {
    pub(crate) fn invalid_request(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: AttemptFailureKind::InvalidRequest,
            category: None,
            source: source.into(),
        }
    }

    pub(crate) fn outcome_unknown(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: AttemptFailureKind::OutcomeUnknown,
            category: None,
            source: source.into(),
        }
    }

    pub(crate) fn protocol_error(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: AttemptFailureKind::OutcomeUnknown,
            category: Some(FailureCategory::Protocol),
            source: source.into(),
        }
    }

    pub(crate) fn from_fixed(error: FixedExchangeError, context: String) -> Self {
        let kind = match error.transmission_state() {
            TransmissionState::NotSent => AttemptFailureKind::NotSent,
            TransmissionState::OutcomeUnknown => AttemptFailureKind::OutcomeUnknown,
        };
        let category = error.known_category();
        Self {
            kind,
            category,
            source: error.into_error().context(context),
        }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> AttemptFailureKind {
        self.kind
    }

    pub(crate) fn into_service_error(self) -> ServiceError {
        let (category, phase, delivery) = match self.kind {
            AttemptFailureKind::InvalidRequest => {
                (FailureCategory::InvalidRequest, FailurePhase::Validation, DeliveryState::NotSent)
            }
            AttemptFailureKind::NotSent => {
                (FailureCategory::Transport, FailurePhase::Upstream, DeliveryState::NotSent)
            }
            AttemptFailureKind::OutcomeUnknown => {
                (FailureCategory::Transport, FailurePhase::Upstream, DeliveryState::OutcomeUnknown)
            }
        };
        let category = self.category.unwrap_or_else(|| {
            if self.source.is::<tokio::time::error::Elapsed>()
                || self.source.is::<tacacsrs_networking::DeadlineElapsed>()
            {
                FailureCategory::Deadline
            } else {
                category
            }
        });
        ServiceError::new(self.to_string(), FailureFacts::new(category, phase, delivery))
    }
}

impl std::fmt::Display for UpstreamRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for UpstreamRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_protocol::failure::RetryAdvice;
    use super::*;

    #[test]
    fn service_errors_preserve_delivery_independently_of_retry_advice() {
        let invalid =
            UpstreamRequestError::invalid_request(anyhow::anyhow!("failure")).into_service_error();
        let uncertain =
            UpstreamRequestError::outcome_unknown(anyhow::anyhow!("failure")).into_service_error();
        let malformed_reply =
            UpstreamRequestError::protocol_error(anyhow::anyhow!("malformed reply"))
                .into_service_error();
        let deadline = UpstreamRequestError::outcome_unknown(tacacsrs_networking::DeadlineElapsed)
            .into_service_error();
        assert_eq!(invalid.message, uncertain.message);
        assert_eq!(invalid.facts.retry_advice(), RetryAdvice::Never);
        assert_eq!(uncertain.facts.retry_advice(), RetryAdvice::Never);
        assert_eq!(malformed_reply.facts.category(), FailureCategory::Protocol);
        assert_eq!(malformed_reply.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(malformed_reply.facts.retry_advice(), RetryAdvice::Never);
        assert_eq!(deadline.facts.category(), FailureCategory::Deadline);
        assert_eq!(deadline.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(deadline.facts.retry_advice(), RetryAdvice::Never);
        assert_eq!(invalid.facts.delivery(), DeliveryState::NotSent);
        assert_eq!(uncertain.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_ne!(invalid.facts.category(), uncertain.facts.category());

        let unsent = UpstreamRequestError {
            kind: AttemptFailureKind::NotSent,
            category: None,
            source: anyhow::anyhow!("failure"),
        }
        .into_service_error();
        assert_eq!(unsent.facts.delivery(), DeliveryState::NotSent);
        assert_eq!(unsent.facts.retry_advice(), RetryAdvice::AfterRecovery);
    }
}
