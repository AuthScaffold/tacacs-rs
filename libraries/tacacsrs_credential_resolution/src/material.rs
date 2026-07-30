//! Typed resolved credential material with non-revealing formatting.

use std::fmt;

use zeroize::Zeroizing;

use crate::CredentialKind;

/// Secret byte ownership that zeroizes its allocation on drop.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Explicitly borrows the secret value for runtime projection.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

/// Public certificate bytes whose debug output reveals length only.
pub struct PublicBytes(Vec<u8>);

impl PublicBytes {
    /// Takes ownership of public bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the public value.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PublicBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicBytes")
            .field("length", &self.0.len())
            .finish()
    }
}

/// Resolved certificate and corresponding private key.
#[derive(Debug)]
pub struct CertificateWithKeyMaterial {
    /// Public end-entity certificate.
    pub certificate: PublicBytes,
    /// Secret private key corresponding to the certificate.
    pub private_key: SecretBytes,
}

/// Resolved public certificate bag.
#[derive(Debug)]
pub struct CertificateBagMaterial {
    /// Public certificates in provider order.
    pub certificates: Vec<PublicBytes>,
}

/// Provider-neutral resolved credential variant.
#[derive(Debug)]
pub enum ResolvedCredential {
    /// End-entity certificate and private key.
    CertificateWithKey(CertificateWithKeyMaterial),
    /// TLS 1.3 external pre-shared key.
    SymmetricKey(SecretBytes),
    /// CA certificate bag.
    CaCertificateBag(CertificateBagMaterial),
    /// End-entity certificate bag.
    EeCertificateBag(CertificateBagMaterial),
}

impl ResolvedCredential {
    /// Returns the material kind for request/response matching.
    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::CertificateWithKey(_) => CredentialKind::CertificateWithKey,
            Self::SymmetricKey(_) => CredentialKind::SymmetricKey,
            Self::CaCertificateBag(_) => CredentialKind::CaCertificateBag,
            Self::EeCertificateBag(_) => CredentialKind::EeCertificateBag,
        }
    }
}
