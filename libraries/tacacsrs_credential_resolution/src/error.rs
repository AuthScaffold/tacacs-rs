//! Sanitized typed resolution errors.

use std::fmt;

use tacacsrs_config::EnumerationRequiredError;

use crate::{CredentialKind, RequestContext, RequestSlot};

/// Stable resolution error category.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ResolutionErrorKind {
    /// Configuration-local credential bundle expansion is required first.
    EnumerationRequired,
    /// A generated central container cannot form a usable request.
    IncompleteRequest,
    /// The provider did not find the requested credential.
    NotFound,
    /// The provider denied access to the requested credential.
    AccessDenied,
    /// The provider returned a malformed or invalid credential.
    InvalidMaterial,
    /// The provider is temporarily unavailable.
    Unavailable,
    /// A response slot is not part of the plan.
    UnexpectedResponse,
    /// More than one response was returned for a slot.
    DuplicateResponse,
    /// No response was returned for a required slot.
    MissingResponse,
    /// The resolved credential variant does not match the request.
    ResponseMismatch,
}

/// Error category that a provider can report for one request.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProviderErrorKind {
    /// The provider did not find the requested credential.
    NotFound,
    /// The provider denied access to the requested credential.
    AccessDenied,
    /// The provider returned a malformed or invalid credential.
    InvalidMaterial,
    /// The provider is temporarily unavailable.
    Unavailable,
}

impl From<ProviderErrorKind> for ResolutionErrorKind {
    fn from(kind: ProviderErrorKind) -> Self {
        match kind {
            ProviderErrorKind::NotFound => Self::NotFound,
            ProviderErrorKind::AccessDenied => Self::AccessDenied,
            ProviderErrorKind::InvalidMaterial => Self::InvalidMaterial,
            ProviderErrorKind::Unavailable => Self::Unavailable,
        }
    }
}

/// Provider-neutral error containing typed context but no raw reference, path,
/// secret value, or provider source error.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolutionError {
    kind: ResolutionErrorKind,
    context: Option<RequestContext>,
    slot: Option<RequestSlot>,
    expected: Option<CredentialKind>,
    actual: Option<CredentialKind>,
}

impl ResolutionError {
    pub(crate) fn incomplete_request(context: RequestContext, expected: CredentialKind) -> Self {
        Self {
            kind: ResolutionErrorKind::IncompleteRequest,
            context: Some(context),
            slot: None,
            expected: Some(expected),
            actual: None,
        }
    }

    /// Creates a sanitized provider error for one request.
    #[must_use]
    pub fn provider(kind: ProviderErrorKind, context: &RequestContext) -> Self {
        Self {
            kind: kind.into(),
            context: Some(context.clone()),
            slot: None,
            expected: None,
            actual: None,
        }
    }

    pub(crate) fn unexpected_response(slot: RequestSlot) -> Self {
        Self::response_error(ResolutionErrorKind::UnexpectedResponse, slot, None, None)
    }

    pub(crate) fn duplicate_response(slot: RequestSlot) -> Self {
        Self::response_error(ResolutionErrorKind::DuplicateResponse, slot, None, None)
    }

    pub(crate) fn missing_response(
        slot: RequestSlot,
        context: RequestContext,
        expected: CredentialKind,
    ) -> Self {
        Self {
            kind: ResolutionErrorKind::MissingResponse,
            context: Some(context),
            slot: Some(slot),
            expected: Some(expected),
            actual: None,
        }
    }

    pub(crate) fn response_mismatch(
        slot: RequestSlot,
        context: RequestContext,
        expected: CredentialKind,
        actual: CredentialKind,
    ) -> Self {
        Self {
            kind: ResolutionErrorKind::ResponseMismatch,
            context: Some(context),
            slot: Some(slot),
            expected: Some(expected),
            actual: Some(actual),
        }
    }

    fn response_error(
        kind: ResolutionErrorKind,
        slot: RequestSlot,
        expected: Option<CredentialKind>,
        actual: Option<CredentialKind>,
    ) -> Self {
        Self {
            kind,
            context: None,
            slot: Some(slot),
            expected,
            actual,
        }
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn kind(&self) -> ResolutionErrorKind {
        self.kind
    }

    /// Returns secret-free server and field context when available.
    #[must_use]
    pub const fn context(&self) -> Option<&RequestContext> {
        self.context.as_ref()
    }

    /// Returns the affected response slot when available.
    #[must_use]
    pub const fn slot(&self) -> Option<RequestSlot> {
        self.slot
    }

    /// Returns the expected credential kind when relevant.
    #[must_use]
    pub const fn expected(&self) -> Option<CredentialKind> {
        self.expected
    }

    /// Returns the actual credential kind for a mismatch.
    #[must_use]
    pub const fn actual(&self) -> Option<CredentialKind> {
        self.actual
    }
}

impl From<EnumerationRequiredError> for ResolutionError {
    fn from(error: EnumerationRequiredError) -> Self {
        let field_path = match error.field() {
            tacacsrs_config::UnexpandedCredentialField::ClientIdentity => {
                "client-identity/credentials-reference"
            }
            tacacsrs_config::UnexpandedCredentialField::ServerAuthentication => {
                "server-authentication/credentials-reference"
            }
        };
        Self {
            kind: ResolutionErrorKind::EnumerationRequired,
            context: Some(RequestContext::new(error.server_name(), field_path)),
            slot: None,
            expected: None,
            actual: None,
        }
    }
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "credential resolution failed: {:?}", self.kind)?;
        if let Some(context) = &self.context {
            write!(
                formatter,
                " for server '{}' field '{}'",
                context.server_name(),
                context.field_path()
            )?;
        }
        if let Some(slot) = self.slot {
            write!(formatter, " at slot {}", slot.index())?;
        }
        if let Some(expected) = self.expected {
            write!(formatter, "; expected {expected:?}")?;
        }
        if let Some(actual) = self.actual {
            write!(formatter, ", received {actual:?}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ResolutionError {}
