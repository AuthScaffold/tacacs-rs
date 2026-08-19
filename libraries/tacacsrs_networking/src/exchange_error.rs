//! Transmission-aware errors for fixed request and reply exchanges.

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

    /// Returns the conservative transmission state.
    #[must_use]
    pub const fn transmission_state(&self) -> TransmissionState {
        self.state
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
