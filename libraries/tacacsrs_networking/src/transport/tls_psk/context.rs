//! OpenSSL TLS 1.3 PSK context construction.
//!
//! This module owns projections from YANG EPSK configuration into OpenSSL
//! ciphersuite and group names, then applies them to a validated `SslContext`.

use anyhow::Context;
use openssl::ssl::{SslContext, SslMethod, SslVerifyMode, SslVersion};
use tacacsrs_config::{EpskSupportedHash, PskDheKeSupportedGroup};
use tacacsrs_credential_resolution::RuntimeServer;

use super::ffi::{prefer_tls13_psk_only_key_exchange, set_tls13_psk_use_session_callback};
use super::tls13_epsk;

/// OpenSSL TLS 1.3 group list derived from `psk-dhe-ke-groups`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PskDheKeGroups {
    openssl_list: String,
}

impl PskDheKeGroups {
    pub(crate) fn from_config(groups: &[PskDheKeSupportedGroup]) -> Option<Self> {
        if groups.is_empty() {
            return None;
        }

        Some(Self {
            openssl_list: groups
                .iter()
                .copied()
                .map(openssl_group_name)
                .collect::<Vec<_>>()
                .join(":"),
        })
    }

    pub(crate) fn as_openssl_list(&self) -> &str {
        &self.openssl_list
    }

    pub(crate) fn unsupported_error(&self, error: &openssl::error::ErrorStack) -> anyhow::Error {
        anyhow::anyhow!(
            "unsupported TLS PSK DHE group list `{}`; ensure the configured psk-dhe-ke-groups are supported by the linked OpenSSL library: {error}",
            self.openssl_list
        )
    }
}

/// OpenSSL projections for the configured TLS 1.3 EPSK hash.
pub(crate) trait EpskSupportedHashExt {
    fn tls13_ciphersuites(self) -> &'static str;
}

impl EpskSupportedHashExt for EpskSupportedHash {
    fn tls13_ciphersuites(self) -> &'static str {
        match self {
            Self::Sha256 => "TLS_AES_128_GCM_SHA256",
            Self::Sha384 => "TLS_AES_256_GCM_SHA384",
        }
    }
}

pub(super) fn create_psk_ssl_context(
    runtime: std::sync::Arc<RuntimeServer>,
    psk_dhe_ke_groups: Option<&PskDheKeGroups>,
) -> anyhow::Result<SslContext> {
    tls13_epsk::validate(&runtime).context("Invalid TLS 1.3 EPSK configuration")?;

    let epsk = tls13_epsk::config(&runtime)?;
    let handshake_hash = epsk.hash;
    let mut ctx_builder = SslContext::builder(SslMethod::tls_client())
        .context("OpenSSL failed to create a TLS 1.3 PSK client context builder")?;

    ctx_builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("OpenSSL failed to enforce TLS 1.3 as the minimum PSK protocol version")?;
    ctx_builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("OpenSSL failed to enforce TLS 1.3 as the maximum PSK protocol version")?;

    ctx_builder.set_verify(SslVerifyMode::NONE);

    set_tls13_psk_use_session_callback(&mut ctx_builder, runtime)
        .context("OpenSSL failed to register TLS 1.3 PSK session callback")?;

    ctx_builder
        .set_ciphersuites(handshake_hash.tls13_ciphersuites())
        .with_context(|| {
            format!(
                "OpenSSL failed to apply TLS 1.3 PSK ciphersuite {}",
                handshake_hash.tls13_ciphersuites()
            )
        })?;

    if let Some(groups) = psk_dhe_ke_groups {
        ctx_builder
            .set_groups_list(groups.as_openssl_list())
            .map_err(|error| groups.unsupported_error(&error))?;
    } else {
        prefer_tls13_psk_only_key_exchange(&mut ctx_builder);
    }

    Ok(ctx_builder.build())
}

fn openssl_group_name(group: PskDheKeSupportedGroup) -> &'static str {
    match group {
        PskDheKeSupportedGroup::X25519 => "X25519",
        PskDheKeSupportedGroup::Secp256r1 => "P-256",
        PskDheKeSupportedGroup::Secp384r1 => "P-384",
        PskDheKeSupportedGroup::Secp521r1 => "P-521",
        PskDheKeSupportedGroup::Ffdhe2048 => "ffdhe2048",
        PskDheKeSupportedGroup::Ffdhe3072 => "ffdhe3072",
        PskDheKeSupportedGroup::Ffdhe4096 => "ffdhe4096",
        PskDheKeSupportedGroup::Ffdhe6144 => "ffdhe6144",
        PskDheKeSupportedGroup::Ffdhe8192 => "ffdhe8192",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacacsrs_config::generated::tacacs_plus::{EpskSupportedHash, Tls13Epsk};
    use tacacsrs_config::keystore::SymmetricKeyInlineDefinition;
    use tacacsrs_credential_resolution::SecretBytes;

    fn epsk_with_hash(hash: EpskSupportedHash) -> Tls13Epsk {
        Tls13Epsk {
            external_identity: "client-id".to_owned(),
            hash,
            context: None,
            target_protocol: None,
            target_kdf: None,
            psk_dhe_ke_groups: vec![],
            inline_definition: Some(SymmetricKeyInlineDefinition {
                key_format: None,
                cleartext_symmetric_key: Some(SecretBytes::new(
                    b"resolved-psk-bytes-with-enough-length".to_vec(),
                )),
            }),
            central_keystore_reference: None,
        }
    }

    #[test]
    fn psk_dhe_ke_groups_maps_absent_groups_to_psk_only() {
        assert_eq!(PskDheKeGroups::from_config(&[]), None);
    }

    #[test]
    fn psk_dhe_ke_groups_maps_config_order_to_openssl_names() {
        let groups = PskDheKeGroups::from_config(&[
            PskDheKeSupportedGroup::X25519,
            PskDheKeSupportedGroup::Secp256r1,
            PskDheKeSupportedGroup::Ffdhe3072,
        ])
        .expect("groups should be configured");

        assert_eq!(groups.as_openssl_list(), "X25519:P-256:ffdhe3072");
    }

    #[test]
    fn epsk_supported_hash_maps_sha256_to_sha256_ciphersuite() {
        let handshake_hash = EpskSupportedHash::Sha256;

        assert_eq!(handshake_hash.tls13_ciphersuites(), "TLS_AES_128_GCM_SHA256");
    }

    #[test]
    fn epsk_supported_hash_maps_sha384_to_sha384_ciphersuite() {
        let handshake_hash = EpskSupportedHash::Sha384;

        assert_eq!(handshake_hash.tls13_ciphersuites(), "TLS_AES_256_GCM_SHA384");
    }

    #[test]
    fn create_psk_ssl_context_accepts_supported_psk_dhe_groups() {
        let epsk = epsk_with_hash(EpskSupportedHash::Sha256);
        let groups = PskDheKeGroups::from_config(&[
            PskDheKeSupportedGroup::X25519,
            PskDheKeSupportedGroup::Secp256r1,
        ])
        .expect("configured groups");

        create_psk_ssl_context(tls13_epsk::test_runtime(epsk), Some(&groups))
            .expect("OpenSSL should accept supported TLS 1.3 groups");
    }

    #[test]
    fn create_psk_ssl_context_accepts_sha384() {
        let epsk = epsk_with_hash(EpskSupportedHash::Sha384);

        create_psk_ssl_context(tls13_epsk::test_runtime(epsk), None)
            .expect("OpenSSL should accept TLS 1.3 SHA-384 PSK sessions");
    }

    #[test]
    fn create_psk_ssl_context_accepts_all_supported_hashes() {
        for hash in EpskSupportedHash::ALL {
            let epsk = epsk_with_hash(*hash);
            let handshake_hash = *hash;

            create_psk_ssl_context(tls13_epsk::test_runtime(epsk), None).unwrap_or_else(|error| {
                panic!(
                    "OpenSSL should accept TLS 1.3 PSK hash {} using ciphersuite {}: {error:#}",
                    handshake_hash.as_rfc7951_str(),
                    handshake_hash.tls13_ciphersuites()
                )
            });
        }
    }

    #[test]
    fn create_psk_ssl_context_accepts_all_supported_psk_dhe_groups() {
        let epsk = epsk_with_hash(EpskSupportedHash::Sha256);
        let groups =
            PskDheKeGroups::from_config(PskDheKeSupportedGroup::ALL).expect("configured groups");

        create_psk_ssl_context(tls13_epsk::test_runtime(epsk), Some(&groups)).unwrap_or_else(
            |error| {
                panic!(
                    "OpenSSL should accept every configured TLS 1.3 PSK-DHE group ({}): {error:#}",
                    groups.as_openssl_list()
                )
            },
        );
    }

    #[test]
    fn create_psk_ssl_context_errors_for_unsupported_group_list() {
        let epsk = epsk_with_hash(EpskSupportedHash::Sha256);
        let groups = PskDheKeGroups {
            openssl_list: "not-a-supported-tls-group".to_owned(),
        };

        let error = create_psk_ssl_context(tls13_epsk::test_runtime(epsk), Some(&groups))
            .expect_err("unsupported OpenSSL group should be rejected");
        let message = error.to_string();

        assert!(message.contains("unsupported TLS PSK DHE group list"));
        assert!(message.contains("not-a-supported-tls-group"));
    }
}
