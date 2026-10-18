//! Transmission-aware errors for fixed request and reply exchanges.

use std::sync::Arc;

use tacacsrs_protocol::failure::FailureCategory;

#[derive(Clone, Debug)]
pub(crate) struct ProtocolFailure {
    source: Arc<anyhow::Error>,
}

impl ProtocolFailure {
    fn new(source: anyhow::Error) -> Self {
        Self {
            source: Arc::new(source),
        }
    }
}

impl std::fmt::Display for ProtocolFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TACACS+ protocol failure")
    }
}

impl std::error::Error for ProtocolFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref().as_ref())
    }
}

pub(crate) fn protocol_failure(source: impl Into<anyhow::Error>) -> anyhow::Error {
    anyhow::Error::new(ProtocolFailure::new(source.into()))
}

pub(crate) fn copy_protocol_failure(source: &anyhow::Error) -> Option<anyhow::Error> {
    source
        .downcast_ref::<ProtocolFailure>()
        .cloned()
        .map(anyhow::Error::new)
}

/// Whether a failed fixed exchange can have reached the TACACS+ server.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TransmissionState {
    /// The request was not submitted to a transport.
    NotSent,
    /// The request was submitted, but no valid reply established its outcome.
    OutcomeUnknown,
}

/// Fixed-exchange error with conservative transmission state.
#[derive(Debug)]
pub struct FixedExchangeError {
    state: TransmissionState,
    source: anyhow::Error,
}

impl FixedExchangeError {
    pub(crate) fn not_sent(source: impl Into<anyhow::Error>) -> Self {
        Self {
            state: TransmissionState::NotSent,
            source: source.into(),
        }
    }

    pub(crate) fn outcome_unknown(source: impl Into<anyhow::Error>) -> Self {
        Self {
            state: TransmissionState::OutcomeUnknown,
            source: source.into(),
        }
    }

    pub(crate) fn protocol_outcome_unknown(source: impl Into<anyhow::Error>) -> Self {
        Self::outcome_unknown(protocol_failure(source))
    }

    /// Returns the conservative transmission state.
    #[must_use]
    pub const fn transmission_state(&self) -> TransmissionState {
        self.state
    }

    /// Returns a known failure category from the detailed error chain.
    #[must_use]
    pub fn known_category(&self) -> Option<FailureCategory> {
        self.source
            .is::<ProtocolFailure>()
            .then_some(FailureCategory::Protocol)
    }

    /// Converts this classified error to its detailed error chain.
    #[must_use]
    pub fn into_error(self) -> anyhow::Error {
        self.source
    }
}

impl std::fmt::Display for FixedExchangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for FixedExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TypedRoot;

    impl std::fmt::Display for TypedRoot {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("typed root")
        }
    }

    impl std::error::Error for TypedRoot {}

    fn is_typed_root(error: &(dyn std::error::Error + 'static)) -> bool {
        error.is::<TypedRoot>()
    }

    #[test]
    fn protocol_category_is_independent_of_transmission_state_and_context() {
        let error = FixedExchangeError::outcome_unknown(
            protocol_failure(anyhow::anyhow!("invalid reply")).context("response rejected"),
        );

        assert_eq!(error.transmission_state(), TransmissionState::OutcomeUnknown);
        assert_eq!(error.known_category(), Some(FailureCategory::Protocol));
        assert_eq!(
            format!("{error:#}"),
            "response rejected: TACACS+ protocol failure: invalid reply"
        );
    }

    #[test]
    fn copied_protocol_failure_retains_its_detailed_chain() {
        let original =
            protocol_failure(anyhow::Error::new(TypedRoot).context("header parse failed"));
        let copied = copy_protocol_failure(&original).unwrap();

        for error in [&original, &copied] {
            assert!(error.is::<ProtocolFailure>());
            assert!(error.chain().any(is_typed_root));
            assert_eq!(
                format!("{error:#}"),
                "TACACS+ protocol failure: header parse failed: typed root"
            );
        }
    }

    #[test]
    fn transport_and_deadline_errors_have_no_known_category() {
        for error in [
            FixedExchangeError::not_sent(anyhow::anyhow!("connect failed")),
            FixedExchangeError::outcome_unknown(crate::DeadlineElapsed),
        ] {
            assert_eq!(error.known_category(), None);
        }
    }
}
