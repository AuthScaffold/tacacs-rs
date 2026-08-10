//! Typed resolved credential material with non-revealing formatting.

use std::fmt;

use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};
use tacacsrs_secrets::SecretBytes;

use crate::CredentialKind;

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

    /// Moves the public value out of its wrapper.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
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
    /// Public key format when the provider returns separate public key data.
    pub public_key_format: Option<PublicKeyFormat>,
    /// Public key data when returned separately from the certificate.
    pub public_key: Option<PublicBytes>,
    /// Provider-supplied private key format.
    pub private_key_format: PrivateKeyFormat,
    /// Public end-entity certificate.
    pub certificate: PublicBytes,
    /// Secret private key corresponding to the certificate.
    pub private_key: SecretBytes,
}

/// One named public certificate from a provider certificate bag.
#[derive(Debug)]
pub struct NamedCertificateMaterial {
    /// Stable provider-supplied certificate name.
    pub name: String,
    /// Public certificate bytes.
    pub certificate: PublicBytes,
}

/// Resolved public certificate bag.
#[derive(Debug)]
pub struct CertificateBagMaterial {
    /// Public certificates in provider order.
    pub certificates: Vec<NamedCertificateMaterial>,
}

/// Resolved symmetric key and its YANG key format metadata.
#[derive(Debug)]
pub struct SymmetricKeyMaterial {
    /// Symmetric key format when known by the provider.
    pub key_format: Option<SymmetricKeyFormat>,
    /// Secret symmetric key bytes.
    pub key: SecretBytes,
}

/// Provider-neutral resolved credential variant.
#[derive(Debug)]
pub enum ResolvedCredential {
    /// End-entity certificate and private key.
    CertificateWithKey(CertificateWithKeyMaterial),
    /// TLS 1.3 external pre-shared key.
    SymmetricKey(SymmetricKeyMaterial),
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

#[cfg(test)]
mod tests {
    use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};

    use super::*;

    #[test]
    fn provider_material_preserves_generated_inline_metadata() {
        let certificate = CertificateWithKeyMaterial {
            public_key_format: Some(PublicKeyFormat::SubjectPublicKeyInfoFormat),
            public_key: Some(PublicBytes::new(b"public-key".to_vec())),
            private_key_format: PrivateKeyFormat::OneAsymmetricKeyFormat,
            certificate: PublicBytes::new(b"certificate".to_vec()),
            private_key: SecretBytes::new(b"private-key".to_vec()),
        };
        let symmetric_key = SymmetricKeyMaterial {
            key_format: Some(SymmetricKeyFormat::OctetStringKeyFormat),
            key: SecretBytes::new(b"symmetric-key".to_vec()),
        };
        let bag = CertificateBagMaterial {
            certificates: vec![NamedCertificateMaterial {
                name: "provider-name".to_owned(),
                certificate: PublicBytes::new(b"bag-certificate".to_vec()),
            }],
        };

        assert_eq!(
            certificate.public_key_format,
            Some(PublicKeyFormat::SubjectPublicKeyInfoFormat),
        );
        assert_eq!(certificate.private_key_format, PrivateKeyFormat::OneAsymmetricKeyFormat,);
        assert_eq!(symmetric_key.key_format, Some(SymmetricKeyFormat::OctetStringKeyFormat),);
        assert_eq!(bag.certificates[0].name, "provider-name");
    }
}
