//! Closed resolution plans from provider-neutral configuration inspection slots.

use std::fmt;

use tacacsrs_config::{
    CentralCredentialReference, CentralCredentialSlot, CentralCredentialUsage, TacacsPlusServer,
    inspect_central_references,
};

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
}

/// Stable request context that contains no endpoint or raw reference value.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestContext {
    server_name: String,
    field_path: &'static str,
}

impl RequestContext {
    pub(crate) fn new(server_name: impl Into<String>, field_path: &'static str) -> Self {
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

    /// Returns the stable RFC model field path.
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
            Self::SymmetricKey(_) | Self::CertificateBag(_) => None,
        }
    }

    /// Returns an opaque symmetric-key reference for provider lookup.
    #[must_use]
    pub fn symmetric_key(&self) -> Option<&str> {
        match self {
            Self::SymmetricKey(reference) => Some(reference),
            Self::CertificateWithKey { .. } | Self::CertificateBag(_) => None,
        }
    }

    /// Returns an opaque certificate-bag reference for provider lookup.
    #[must_use]
    pub fn certificate_bag(&self) -> Option<&str> {
        match self {
            Self::CertificateBag(reference) => Some(reference),
            Self::CertificateWithKey { .. } | Self::SymmetricKey(_) => None,
        }
    }
}

impl fmt::Debug for CredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

/// Ordered closed request plan for one direct or enumerated server.
pub struct ResolutionPlan {
    requests: Vec<CredentialRequest>,
}

impl ResolutionPlan {
    /// Builds a deterministic provider-neutral plan from one server.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`ResolutionErrorKind::EnumerationRequired`](crate::ResolutionErrorKind::EnumerationRequired)
    /// if configuration-local bundle references remain. Returns
    /// [`ResolutionErrorKind::IncompleteRequest`](crate::ResolutionErrorKind::IncompleteRequest)
    /// if a central container lacks fields that the provider request requires.
    pub fn from_server(server: &TacacsPlusServer) -> Result<Self, ResolutionError> {
        let slots = inspect_central_references(server).map_err(ResolutionError::from)?;
        let requests = slots
            .into_iter()
            .enumerate()
            .map(|(index, slot)| request_from_slot(RequestSlot(index), slot))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { requests })
    }

    /// Returns all requests in deterministic field order.
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

fn request_from_slot(
    slot: RequestSlot,
    inspected: CentralCredentialSlot<'_>,
) -> Result<CredentialRequest, ResolutionError> {
    let usage = inspected.usage();
    let context = RequestContext {
        server_name: inspected.server_name().to_owned(),
        field_path: usage.field_path(),
    };
    let (kind, reference) = match (usage, inspected.reference()) {
        (
            CentralCredentialUsage::ClientCertificateWithKey,
            CentralCredentialReference::CertificateWithKey {
                asymmetric_key,
                certificate,
            },
        ) if asymmetric_key.is_some() || certificate.is_some() => (
            CredentialKind::CertificateWithKey,
            CredentialReference::CertificateWithKey {
                asymmetric_key: asymmetric_key.map(str::to_owned),
                certificate: certificate.map(str::to_owned),
            },
        ),
        (
            CentralCredentialUsage::ClientTls13Epsk,
            CentralCredentialReference::SymmetricKey(reference),
        ) => {
            (CredentialKind::SymmetricKey, CredentialReference::SymmetricKey(reference.to_owned()))
        }
        (
            CentralCredentialUsage::ServerCaCertificateBag,
            CentralCredentialReference::CertificateBag(reference),
        ) => (
            CredentialKind::CaCertificateBag,
            CredentialReference::CertificateBag(reference.to_owned()),
        ),
        (
            CentralCredentialUsage::ServerEeCertificateBag,
            CentralCredentialReference::CertificateBag(reference),
        ) => (
            CredentialKind::EeCertificateBag,
            CredentialReference::CertificateBag(reference.to_owned()),
        ),
        _ => return Err(ResolutionError::incomplete_request(context, kind_for_usage(usage))),
    };

    Ok(CredentialRequest {
        slot,
        context,
        kind,
        reference,
    })
}

const fn kind_for_usage(usage: CentralCredentialUsage) -> CredentialKind {
    match usage {
        CentralCredentialUsage::ClientCertificateWithKey => CredentialKind::CertificateWithKey,
        CentralCredentialUsage::ClientTls13Epsk => CredentialKind::SymmetricKey,
        CentralCredentialUsage::ServerCaCertificateBag => CredentialKind::CaCertificateBag,
        CentralCredentialUsage::ServerEeCertificateBag => CredentialKind::EeCertificateBag,
    }
}
