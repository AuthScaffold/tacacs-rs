//! Classified upstream request failures used by replay policy.

use tacacsrs_networking::{FixedExchangeError, TransmissionState};

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
    source: anyhow::Error,
}

impl UpstreamRequestError {
    pub(crate) fn invalid_request(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: AttemptFailureKind::InvalidRequest,
            source: source.into(),
        }
    }

    pub(crate) fn outcome_unknown(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: AttemptFailureKind::OutcomeUnknown,
            source: source.into(),
        }
    }

    pub(crate) fn from_fixed(error: FixedExchangeError, context: String) -> Self {
        let kind = match error.transmission_state() {
            TransmissionState::NotSent => AttemptFailureKind::NotSent,
            TransmissionState::OutcomeUnknown => AttemptFailureKind::OutcomeUnknown,
        };
        Self {
            kind,
            source: error.into_error().context(context),
        }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> AttemptFailureKind {
        self.kind
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
