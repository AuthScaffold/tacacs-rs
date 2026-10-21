//! Maps provider key encodings to canonical YANG identities.

use tacacsrs_credential_resolution::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};

use crate::crypto_types;

impl From<PrivateKeyFormat> for crypto_types::PrivateKeyFormat {
    fn from(format: PrivateKeyFormat) -> Self {
        match format {
            PrivateKeyFormat::RsaPrivateKeyFormat => Self::RsaPrivateKeyFormat,
            PrivateKeyFormat::EcPrivateKeyFormat => Self::EcPrivateKeyFormat,
            PrivateKeyFormat::OneAsymmetricKeyFormat => Self::OneAsymmetricKeyFormat,
        }
    }
}

impl From<PublicKeyFormat> for crypto_types::PublicKeyFormat {
    fn from(format: PublicKeyFormat) -> Self {
        match format {
            PublicKeyFormat::SshPublicKeyFormat => Self::SshPublicKeyFormat,
            PublicKeyFormat::SubjectPublicKeyInfoFormat => Self::SubjectPublicKeyInfoFormat,
        }
    }
}

impl From<SymmetricKeyFormat> for crypto_types::SymmetricKeyFormat {
    fn from(format: SymmetricKeyFormat) -> Self {
        match format {
            SymmetricKeyFormat::OctetStringKeyFormat => Self::OctetStringKeyFormat,
            SymmetricKeyFormat::OneSymmetricKeyFormat => Self::OneSymmetricKeyFormat,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_formats_cover_every_generated_identity() {
        assert_eq!(
            [
                PrivateKeyFormat::RsaPrivateKeyFormat,
                PrivateKeyFormat::EcPrivateKeyFormat,
                PrivateKeyFormat::OneAsymmetricKeyFormat
            ]
            .map(crypto_types::PrivateKeyFormat::from),
            crypto_types::PrivateKeyFormat::ALL,
        );
        assert_eq!(
            [
                PublicKeyFormat::SshPublicKeyFormat,
                PublicKeyFormat::SubjectPublicKeyInfoFormat
            ]
            .map(crypto_types::PublicKeyFormat::from),
            crypto_types::PublicKeyFormat::ALL,
        );
        assert_eq!(
            [
                SymmetricKeyFormat::OctetStringKeyFormat,
                SymmetricKeyFormat::OneSymmetricKeyFormat
            ]
            .map(crypto_types::SymmetricKeyFormat::from),
            crypto_types::SymmetricKeyFormat::ALL,
        );
    }
}
