//! Closed resolution plans from typed provider requests.

use std::fmt;

use crate::ResolutionError;

/// Stable ordinal identifying one request within a [`ResolutionPlan`].
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestSlot(usize);

impl RequestSlot {
    /// Reconstructs a slot index for a batched provider response.
    #[must_use]
    pub const fn from_index(index: usize) -> Self {
        Self(index)
    }

    /// Returns the zero-based deterministic slot index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// Expected resolved credential variant for a request.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CredentialKind {
    /// End-entity certificate plus private key.
    CertificateWithKey,
    /// TLS 1.3 external pre-shared key.
    SymmetricKey,
    /// CA certificate bag.
    CaCertificateBag,
    /// End-entity certificate bag.
    EeCertificateBag,
    /// Certificate revocation lists used for server-chain authentication.
    CertificateRevocationLists,
}

/// Stable request context that contains no endpoint or raw reference value.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestContext {
    server_name: String,
    field_path: &'static str,
}

impl RequestContext {
    /// Creates diagnostic context without storing a credential reference.
    #[must_use]
    pub fn new(server_name: impl Into<String>, field_path: &'static str) -> Self {
        Self {
            server_name: server_name.into(),
            field_path,
        }
    }

    /// Returns the configured server name.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns the caller's stable diagnostic field path.
    #[must_use]
    pub const fn field_path(&self) -> &'static str {
        self.field_path
    }
}

/// Owned opaque reference passed to a provider only through explicit access.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CredentialReference {
    /// Structured central certificate-with-key reference.
    CertificateWithKey {
        /// Opaque central asymmetric-key reference, when present.
        asymmetric_key: Option<String>,
        /// Opaque central certificate reference, when present.
        certificate: Option<String>,
    },
    /// Opaque central symmetric-key reference.
    SymmetricKey(String),
    /// Opaque central truststore certificate-bag reference.
    CertificateBag(String),
    /// Opaque reference to a complete certificate revocation list set.
    CertificateRevocationLists(String),
}

impl CredentialReference {
    /// Returns the structured central certificate-with-key components.
    #[must_use]
    pub fn certificate_with_key(&self) -> Option<(Option<&str>, Option<&str>)> {
        match self {
            Self::CertificateWithKey {
                asymmetric_key,
                certificate,
            } => Some((asymmetric_key.as_deref(), certificate.as_deref())),
            Self::SymmetricKey(_)
            | Self::CertificateBag(_)
            | Self::CertificateRevocationLists(_) => None,
        }
    }

    /// Returns an opaque symmetric-key reference for provider lookup.
    #[must_use]
    pub fn symmetric_key(&self) -> Option<&str> {
        match self {
            Self::SymmetricKey(reference) => Some(reference),
            Self::CertificateWithKey { .. }
            | Self::CertificateBag(_)
            | Self::CertificateRevocationLists(_) => None,
        }
    }

    /// Returns an opaque certificate-bag reference for provider lookup.
    #[must_use]
    pub fn certificate_bag(&self) -> Option<&str> {
        match self {
            Self::CertificateBag(reference) => Some(reference),
            Self::CertificateWithKey { .. }
            | Self::SymmetricKey(_)
            | Self::CertificateRevocationLists(_) => None,
        }
    }

    /// Returns the opaque reference for revocation-evidence lookup.
    #[must_use]
    pub fn certificate_revocation_lists(&self) -> Option<&str> {
        match self {
            Self::CertificateRevocationLists(reference) => Some(reference),
            _ => None,
        }
    }
}

impl fmt::Debug for CredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateRevocationLists(_) => formatter
                .debug_tuple("CertificateRevocationLists")
                .field(&"<redacted>")
                .finish(),
            Self::CertificateWithKey { .. } => formatter
                .debug_struct("CertificateWithKey")
                .field("reference", &"<redacted>")
                .finish(),
            Self::SymmetricKey(_) => formatter
                .debug_tuple("SymmetricKey")
                .field(&"<redacted>")
                .finish(),
            Self::CertificateBag(_) => formatter
                .debug_tuple("CertificateBag")
                .field(&"<redacted>")
                .finish(),
        }
    }
}

/// One typed provider-neutral resolution request.
pub struct CredentialRequest {
    slot: RequestSlot,
    context: RequestContext,
    kind: CredentialKind,
    reference: CredentialReference,
}

impl CredentialRequest {
    /// Returns the request slot.
    #[must_use]
    pub const fn slot(&self) -> RequestSlot {
        self.slot
    }

    /// Returns the stable secret-free request context.
    #[must_use]
    pub const fn context(&self) -> &RequestContext {
        &self.context
    }

    /// Returns the expected credential kind.
    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// Exposes the opaque owned reference to a provider.
    #[must_use]
    pub const fn reference(&self) -> &CredentialReference {
        &self.reference
    }
}

impl fmt::Debug for CredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRequest")
            .field("slot", &self.slot)
            .field("context", &self.context)
            .field("kind", &self.kind)
            .field("reference", &"<redacted>")
            .finish()
    }
}

/// Ordered closed request plan with deterministic response slots.
pub struct ResolutionPlan {
    requests: Vec<CredentialRequest>,
}

impl ResolutionPlan {
    /// Builds a closed plan in input order and assigns deterministic slots.
    ///
    /// # Errors
    ///
    /// Returns an error if a reference does not match its expected kind or a
    /// certificate reference contains neither component.
    pub fn new(
        requests: impl IntoIterator<Item = (RequestContext, CredentialKind, CredentialReference)>,
    ) -> Result<Self, ResolutionError> {
        let requests = requests
            .into_iter()
            .enumerate()
            .map(|(index, (context, kind, reference))| {
                let valid = match (&reference, kind) {
                    (
                        CredentialReference::CertificateWithKey {
                            asymmetric_key,
                            certificate,
                        },
                        CredentialKind::CertificateWithKey,
                    ) => asymmetric_key.is_some() || certificate.is_some(),
                    (
                        CredentialReference::CertificateRevocationLists(_),
                        CredentialKind::CertificateRevocationLists,
                    )
                    | (CredentialReference::SymmetricKey(_), CredentialKind::SymmetricKey)
                    | (
                        CredentialReference::CertificateBag(_),
                        CredentialKind::CaCertificateBag | CredentialKind::EeCertificateBag,
                    ) => true,
                    _ => false,
                };
                if !valid {
                    return Err(ResolutionError::incomplete_request(context, kind));
                }
                Ok(CredentialRequest {
                    slot: RequestSlot(index),
                    context,
                    kind,
                    reference,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { requests })
    }

    /// Returns all requests in their original input order.
    #[must_use]
    pub fn requests(&self) -> &[CredentialRequest] {
        &self.requests
    }

    /// Returns the number of expected responses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns whether the plan contains no provider requests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn reverse_requests_for_test(&mut self) {
        self.requests.reverse();
    }
}

impl fmt::Debug for ResolutionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolutionPlan")
            .field("requests", &self.requests)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_plan_preserves_order_and_redacts_references() {
        let plan = ResolutionPlan::new([
            (
                RequestContext::new("first", "psk"),
                CredentialKind::SymmetricKey,
                CredentialReference::SymmetricKey("private-reference".to_owned()),
            ),
            (
                RequestContext::new("second", "ca"),
                CredentialKind::CaCertificateBag,
                CredentialReference::CertificateBag("private-bag".to_owned()),
            ),
        ])
        .unwrap();
        assert_eq!(plan.requests()[0].slot().index(), 0);
        assert_eq!(plan.requests()[1].slot().index(), 1);
        assert_eq!(plan.requests()[0].context().server_name(), "first");
        assert_eq!(plan.requests()[1].context().server_name(), "second");
        assert!(!format!("{plan:?}").contains("private-reference"));
        assert!(!format!("{plan:?}").contains("private-bag"));
    }

    #[test]
    fn neutral_plan_rejects_mismatched_and_incomplete_references() {
        for reference in [
            CredentialReference::SymmetricKey("private-reference".to_owned()),
            CredentialReference::CertificateWithKey {
                asymmetric_key: None,
                certificate: None,
            },
        ] {
            let error = ResolutionPlan::new([(
                RequestContext::new("server", "certificate"),
                CredentialKind::CertificateWithKey,
                reference,
            )])
            .unwrap_err();
            assert_eq!(error.kind(), crate::ResolutionErrorKind::IncompleteRequest);
            assert!(!format!("{error:?}").contains("private-reference"));
        }
    }
}
