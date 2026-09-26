//! OpenSSL TLS 1.3 PSK context construction from explicit transport inputs.

use anyhow::{Context, ensure};
use openssl::hash::MessageDigest;
use openssl::ssl::{SslContext, SslMethod, SslVerifyMode, SslVersion};
use tacacsrs_secrets::SecretBytes;

use super::ffi::{
    prefer_tls13_psk_only_key_exchange, set_tls13_psk_use_session_callback, OpenSslPskCallbackState,
};

/// RFC 9257 section 6 requires at least 128 bits of PSK material.
const MIN_PSK_KEY_LENGTH: usize = 16;

/// Hash bound to a TLS 1.3 external PSK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PskHash {
    /// SHA-256 with AES-128-GCM.
    Sha256,
    /// SHA-384 with AES-256-GCM.
    Sha384,
}

impl PskHash {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
        }
    }

    pub(crate) const fn tls13_ciphersuites(self) -> &'static str {
        match self {
            Self::Sha256 => "TLS_AES_128_GCM_SHA256",
            Self::Sha384 => "TLS_AES_256_GCM_SHA384",
        }
    }
}

/// A supported TLS 1.3 group for ephemeral key exchange with a PSK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PskDheGroup {
    /// X25519 elliptic curve.
    X25519,
    /// NIST P-256 elliptic curve.
    Secp256r1,
    /// NIST P-384 elliptic curve.
    Secp384r1,
    /// NIST P-521 elliptic curve.
    Secp521r1,
    /// 2048-bit finite-field group.
    Ffdhe2048,
    /// 3072-bit finite-field group.
    Ffdhe3072,
    /// 4096-bit finite-field group.
    Ffdhe4096,
    /// 6144-bit finite-field group.
    Ffdhe6144,
    /// 8192-bit finite-field group.
    Ffdhe8192,
}

impl PskDheGroup {
    const fn openssl_name(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::Secp256r1 => "P-256",
            Self::Secp384r1 => "P-384",
            Self::Secp521r1 => "P-521",
            Self::Ffdhe2048 => "ffdhe2048",
            Self::Ffdhe3072 => "ffdhe3072",
            Self::Ffdhe4096 => "ffdhe4096",
            Self::Ffdhe6144 => "ffdhe6144",
            Self::Ffdhe8192 => "ffdhe8192",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PskDheKeGroups {
    openssl_list: String,
}

impl PskDheKeGroups {
    pub(crate) fn new(groups: &[PskDheGroup]) -> Option<Self> {
        if groups.is_empty() {
            return None;
        }
        Some(Self {
            openssl_list: groups
                .iter()
                .copied()
                .map(PskDheGroup::openssl_name)
                .collect::<Vec<_>>()
                .join(":"),
        })
    }

    pub(crate) fn as_openssl_list(&self) -> &str {
        &self.openssl_list
    }
}

pub(super) fn create_psk_ssl_context(
    identity: &str,
    key: &[u8],
    handshake_hash: PskHash,
    psk_dhe_ke_groups: Option<&PskDheKeGroups>,
) -> anyhow::Result<SslContext> {
    ensure!(!identity.is_empty(), "PSK identity must not be empty");
    ensure!(
        !identity.contains('\0'),
        "PSK identity must not contain NUL bytes because OpenSSL receives it as a byte string"
    );
    ensure!(key.len() >= MIN_PSK_KEY_LENGTH, "PSK key must be at least {MIN_PSK_KEY_LENGTH} bytes (128 bits) as required by RFC 9257 section 6; got {} bytes", key.len());
    let mut builder = SslContext::builder(SslMethod::tls_client())
        .context("OpenSSL failed to create a TLS 1.3 PSK client context builder")?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_verify(SslVerifyMode::NONE);
    set_tls13_psk_use_session_callback(
        &mut builder,
        OpenSslPskCallbackState {
            identity: identity.as_bytes().into(),
            key: SecretBytes::new(key.to_vec()),
            digest: match handshake_hash {
                PskHash::Sha256 => MessageDigest::sha256(),
                PskHash::Sha384 => MessageDigest::sha384(),
            },
            cipher_suite: handshake_hash.tls13_ciphersuites(),
        },
    )
    .context("OpenSSL failed to register TLS 1.3 PSK session callback")?;
    builder
        .set_ciphersuites(handshake_hash.tls13_ciphersuites())
        .context("OpenSSL failed to apply TLS 1.3 PSK ciphersuite")?;
    if let Some(groups) = psk_dhe_ke_groups {
        builder
            .set_groups_list(groups.as_openssl_list())
            .with_context(|| {
                format!("unsupported TLS PSK DHE group list `{}`", groups.as_openssl_list())
            })?;
    } else {
        prefer_tls13_psk_only_key_exchange(&mut builder);
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"resolved-psk-bytes-with-enough-length";

    #[test]
    fn groups_preserve_order_and_empty_means_psk_only() {
        assert_eq!(PskDheKeGroups::new(&[]), None);
        let groups = PskDheKeGroups::new(&[
            PskDheGroup::X25519,
            PskDheGroup::Secp256r1,
            PskDheGroup::Ffdhe3072,
        ])
        .unwrap();
        assert_eq!(groups.as_openssl_list(), "X25519:P-256:ffdhe3072");
    }

    #[test]
    fn native_context_accepts_both_hashes_and_all_supported_groups() {
        let groups = PskDheKeGroups::new(&[
            PskDheGroup::X25519,
            PskDheGroup::Secp256r1,
            PskDheGroup::Secp384r1,
            PskDheGroup::Secp521r1,
            PskDheGroup::Ffdhe2048,
            PskDheGroup::Ffdhe3072,
            PskDheGroup::Ffdhe4096,
            PskDheGroup::Ffdhe6144,
            PskDheGroup::Ffdhe8192,
        ]);
        for hash in [PskHash::Sha256, PskHash::Sha384] {
            create_psk_ssl_context("client", KEY, hash, groups.as_ref()).unwrap();
            create_psk_ssl_context("client", KEY, hash, None).unwrap();
        }
        assert_eq!(PskHash::Sha256.tls13_ciphersuites(), "TLS_AES_128_GCM_SHA256");
        assert_eq!(PskHash::Sha384.tls13_ciphersuites(), "TLS_AES_256_GCM_SHA384");
    }

    #[test]
    fn rejects_invalid_identity_and_unsupported_native_groups() {
        for identity in ["", "client\0identity"] {
            assert!(create_psk_ssl_context(identity, KEY, PskHash::Sha256, None).is_err());
        }
        let groups = PskDheKeGroups {
            openssl_list: "not-a-supported-tls-group".to_owned(),
        };
        assert!(create_psk_ssl_context("client", KEY, PskHash::Sha256, Some(&groups))
            .unwrap_err()
            .to_string()
            .contains("unsupported TLS PSK DHE group list"));
    }
}
