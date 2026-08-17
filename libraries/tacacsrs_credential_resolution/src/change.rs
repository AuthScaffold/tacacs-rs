//! Provider-neutral credential change notifications for orchestration.

use std::fmt;
use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;

use crate::{CredentialKind, CredentialReference};

/// Scope affected by a credential provider change.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CredentialChangeScope {
    /// One known provider reference changed.
    Known {
        /// Expected credential kind.
        kind: CredentialKind,
        /// Opaque provider reference identity.
        reference: CredentialReference,
    },
    /// The provider cannot identify a narrower scope safely.
    Unknown,
}

impl fmt::Debug for CredentialChangeScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known { kind, .. } => formatter
                .debug_struct("Known")
                .field("kind", kind)
                .field("reference", &"<redacted>")
                .finish(),
            Self::Unknown => formatter.write_str("Unknown"),
        }
    }
}

/// Credential change-stream lifecycle event.
#[derive(Clone, Eq, PartialEq)]
pub enum CredentialChangeEvent {
    /// A credential changed within the supplied scope.
    Changed(CredentialChangeScope),
    /// The provider notification stream became unavailable.
    Unavailable,
    /// The provider notification stream is available again.
    Recovered,
}

impl fmt::Debug for CredentialChangeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Changed(scope) => formatter.debug_tuple("Changed").field(scope).finish(),
            Self::Unavailable => formatter.write_str("Unavailable"),
            Self::Recovered => formatter.write_str("Recovered"),
        }
    }
}

/// Sanitized error from an attempt to establish a credential change stream.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CredentialChangeError;

impl fmt::Display for CredentialChangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential change notifications unavailable")
    }
}

impl std::error::Error for CredentialChangeError {}

/// Stream returned by a [`CredentialChangeSource`].
pub type CredentialChangeStream =
    Pin<Box<dyn Stream<Item = CredentialChangeEvent> + Send + 'static>>;

/// Source of credential provider change notifications.
#[async_trait]
pub trait CredentialChangeSource: Send + Sync {
    /// Establishes a new provider notification stream.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the subscription cannot be established.
    async fn subscribe(&self) -> Result<CredentialChangeStream, CredentialChangeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_event_debug_redacts_reference_identity() {
        let event = CredentialChangeEvent::Changed(CredentialChangeScope::Known {
            kind: CredentialKind::SymmetricKey,
            reference: CredentialReference::SymmetricKey("reference-sentinel".to_owned()),
        });

        let debug = format!("{event:?}");
        assert!(debug.contains("SymmetricKey"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("reference-sentinel"));
    }
}
