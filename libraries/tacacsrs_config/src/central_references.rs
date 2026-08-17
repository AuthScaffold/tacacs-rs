//! Provider-neutral inspection of unresolved central credential references.
//!
//! This module borrows generated model values and creates deterministic slots.
//! It does not access a provider or interpret opaque reference values.

use std::fmt;

use crate::TacacsPlusServer;

/// RFC credential usage for one central reference slot.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CentralCredentialUsage {
    /// TLS client certificate and its private key.
    ClientCertificateWithKey,
    /// TLS 1.3 external pre-shared key.
    ClientTls13Epsk,
    /// CA certificate bag that authenticates a server chain.
    ServerCaCertificateBag,
    /// End-entity certificate bag for exact server authentication.
    ServerEeCertificateBag,
}

impl CentralCredentialUsage {
    /// Returns the stable RFC model field path for this usage.
    #[must_use]
    pub const fn field_path(self) -> &'static str {
        match self {
            Self::ClientCertificateWithKey => "client-identity/certificate",
            Self::ClientTls13Epsk => "client-identity/tls13-epsk",
            Self::ServerCaCertificateBag => "server-authentication/ca-certs",
            Self::ServerEeCertificateBag => "server-authentication/ee-certs",
        }
    }
}

/// Borrowed central reference for one credential usage.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CentralCredentialReference<'a> {
    /// Central certificate-with-key reference from RFC 9642.
    CertificateWithKey {
        /// Opaque asymmetric-key reference from the generated model.
        asymmetric_key: Option<&'a str>,
        /// Opaque certificate reference from the generated model.
        certificate: Option<&'a str>,
    },
    /// Opaque central symmetric-key reference used by TLS 1.3 EPSK.
    SymmetricKey(&'a str),
    /// Opaque central truststore certificate-bag reference.
    CertificateBag(&'a str),
}

impl fmt::Debug for CentralCredentialReference<'_> {
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

/// Deterministic central credential slot from an enumerated server.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CentralCredentialSlot<'a> {
    server_name: &'a str,
    usage: CentralCredentialUsage,
    reference: CentralCredentialReference<'a>,
}

impl CentralCredentialSlot<'_> {
    /// Returns the server name that provides stable request context.
    #[must_use]
    pub const fn server_name(&self) -> &str {
        self.server_name
    }

    /// Returns the RFC credential usage for this slot.
    #[must_use]
    pub const fn usage(&self) -> CentralCredentialUsage {
        self.usage
    }

    /// Returns the borrowed opaque reference for resolver planning.
    #[must_use]
    pub const fn reference(&self) -> CentralCredentialReference<'_> {
        self.reference
    }
}

impl fmt::Debug for CentralCredentialSlot<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CentralCredentialSlot")
            .field("server_name", &self.server_name)
            .field("usage", &self.usage)
            .field("reference", &"<redacted>")
            .finish()
    }
}

/// Local credential field that requires enumeration before inspection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UnexpandedCredentialField {
    /// `client-identity/credentials-reference` remains present.
    ClientIdentity,
    /// `server-authentication/credentials-reference` remains present.
    ServerAuthentication,
}

impl UnexpandedCredentialField {
    const fn field_path(self) -> &'static str {
        match self {
            Self::ClientIdentity => "client-identity/credentials-reference",
            Self::ServerAuthentication => "server-authentication/credentials-reference",
        }
    }
}

/// Error for a local bundle reference that requires server enumeration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EnumerationRequiredError {
    server_name: String,
    field: UnexpandedCredentialField,
}

impl EnumerationRequiredError {
    /// Returns the server whose local reference remains unresolved.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns the local credential field requiring enumeration.
    #[must_use]
    pub const fn field(&self) -> UnexpandedCredentialField {
        self.field
    }
}

impl fmt::Display for EnumerationRequiredError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "server '{}': {} must be expanded with enumerate_server or enumerate_servers before central credential inspection",
            self.server_name,
            self.field.field_path(),
        )
    }
}

impl std::error::Error for EnumerationRequiredError {}

/// Inspect central references on one direct or enumerated server.
///
/// The function returns slots in stable field order: client certificate, client EPSK,
/// server CA bag, then server end-entity bag. Inline fields produce no slot.
/// The function preserves incomplete central containers as slots. The
/// resolution planning layer decides if it can create a usable request.
///
/// # Errors
///
/// Returns [`EnumerationRequiredError`] when a local client or server
/// credential bundle reference remains. The error omits the raw reference.
pub fn inspect_central_references(
    server: &TacacsPlusServer,
) -> Result<Vec<CentralCredentialSlot<'_>>, EnumerationRequiredError> {
    if server
        .client_identity
        .as_ref()
        .is_some_and(|identity| identity.credentials_reference.is_some())
    {
        return Err(EnumerationRequiredError {
            server_name: server.name.clone(),
            field: UnexpandedCredentialField::ClientIdentity,
        });
    }
    if server
        .server_authentication
        .as_ref()
        .is_some_and(|authentication| authentication.credentials_reference.is_some())
    {
        return Err(EnumerationRequiredError {
            server_name: server.name.clone(),
            field: UnexpandedCredentialField::ServerAuthentication,
        });
    }

    let mut slots = Vec::with_capacity(4);
    if let Some(identity) = &server.client_identity {
        if let Some(reference) = identity
            .certificate
            .as_ref()
            .and_then(|certificate| certificate.central_keystore_reference.as_ref())
        {
            slots.push(CentralCredentialSlot {
                server_name: &server.name,
                usage: CentralCredentialUsage::ClientCertificateWithKey,
                reference: CentralCredentialReference::CertificateWithKey {
                    asymmetric_key: reference.asymmetric_key.as_deref(),
                    certificate: reference.certificate.as_deref(),
                },
            });
        }
        if let Some(reference) = identity
            .tls13_epsk
            .as_ref()
            .and_then(|epsk| epsk.central_keystore_reference.as_deref())
        {
            slots.push(CentralCredentialSlot {
                server_name: &server.name,
                usage: CentralCredentialUsage::ClientTls13Epsk,
                reference: CentralCredentialReference::SymmetricKey(reference),
            });
        }
    }
    if let Some(authentication) = &server.server_authentication {
        if let Some(reference) = authentication
            .ca_certs
            .as_ref()
            .and_then(|certificates| certificates.central_truststore_reference.as_deref())
        {
            slots.push(CentralCredentialSlot {
                server_name: &server.name,
                usage: CentralCredentialUsage::ServerCaCertificateBag,
                reference: CentralCredentialReference::CertificateBag(reference),
            });
        }
        if let Some(reference) = authentication
            .ee_certs
            .as_ref()
            .and_then(|certificates| certificates.central_truststore_reference.as_deref())
        {
            slots.push(CentralCredentialSlot {
                server_name: &server.name,
                usage: CentralCredentialUsage::ServerEeCertificateBag,
                reference: CentralCredentialReference::CertificateBag(reference),
            });
        }
    }

    Ok(slots)
}
