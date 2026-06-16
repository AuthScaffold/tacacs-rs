//! Build TLS 1.3 PSK connections directly from a [`TacacsPlusServer`]
//! configuration.
//!
//! This module keeps the YANG-derived TLS 1.3 EPSK configuration as the
//! first-class runtime input and owns only the OpenSSL-specific projections such
//! as ciphersuite and group names.

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use tacacsrs_config::{EpskSupportedHash, PskDheKeSupportedGroup, TacacsPlusServer, Tls13Epsk};

use super::PskClientConfig;

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

/// TLS 1.3 EPSK handshake hash selected by configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PskHandshakeHash {
    Sha256,
    Sha384,
}

impl PskHandshakeHash {
    pub(crate) fn from_config(hash: EpskSupportedHash) -> Self {
        match hash {
            EpskSupportedHash::Sha256 => Self::Sha256,
            EpskSupportedHash::Sha384 => Self::Sha384,
        }
    }

    pub(crate) const fn tls13_ciphersuites(self) -> &'static str {
        match self {
            Self::Sha256 => "TLS_AES_128_GCM_SHA256",
            Self::Sha384 => "TLS_AES_256_GCM_SHA384",
        }
    }

    pub(crate) const fn as_name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
        }
    }
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

/// Returns `true` when `server` carries a TLS 1.3 PSK client identity that
/// would direct the dispatcher to use the PSK transport.
#[must_use]
pub(crate) fn server_has_psk(server: &TacacsPlusServer) -> bool {
    server
        .client_identity
        .as_ref()
        .is_some_and(|ci| ci.tls13_epsk.is_some())
}

/// Establishes a TLS 1.3 PSK connection over an existing TCP stream using the
/// PSK material carried in `server`.
///
/// The PSK identity is taken from `client-identity.tls13-epsk.external-identity`
/// and the symmetric key from
/// `client-identity.tls13-epsk.inline-definition.cleartext-symmetric-key`.
///
/// # Errors
///
/// Returns an error if the configured PSK material is invalid (e.g. empty key,
/// identity containing a NUL byte) or the TLS-PSK handshake fails. Callers
/// should ensure [`server_has_psk`] returns `true` before invoking this
/// function — if no PSK is configured, an error is returned because there is
/// no key material to negotiate with.
pub(crate) async fn establish_from_server(
    server: &TacacsPlusServer,
    address: &str,
    tcp_stream: TcpStream,
) -> Result<SslStream<TcpStream>> {
    let epsk = tls13_epsk(server)?;

    log::debug!("Negotiating TLS-PSK handshake with {address}");

    let tls_stream = PskClientConfig::prepare(epsk)
        .context("Invalid TLS PSK OpenSSL configuration")?
        .connect(address, tcp_stream)
        .await
        .inspect_err(|e| log::warn!("TLS-PSK handshake with {address} failed: {e:#}"))
        .context("Failed to establish TLS PSK connection")?;

    log::debug!("TLS-PSK connection to {address} ready");
    Ok(tls_stream)
}

fn tls13_epsk(server: &TacacsPlusServer) -> Result<&Tls13Epsk> {
    server
        .client_identity
        .as_ref()
        .and_then(|ci| ci.tls13_epsk.as_ref())
        .ok_or_else(|| anyhow::anyhow!("server has no TLS 1.3 PSK client-identity"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tls_psk::create_psk_ssl_context;
    use tacacsrs_config::generated::tacacs_plus::{
        EpskSupportedHash, Tls13Epsk, TlsClientClientIdentity,
    };
    use tacacsrs_config::keystore::SymmetricKeyInlineDefinition;

    fn server_template() -> TacacsPlusServer {
        TacacsPlusServer {
            name: "test".to_owned(),
            server_type: tacacsrs_config::TacacsPlusServerType::all(),
            address: "10.0.0.1".to_owned(),
            port: 49,
            shared_secret: None,
            timeout: 5,
            single_connection: false,
            domain_name: None,
            sni_enabled: None,
            client_identity: None,
            server_authentication: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        }
    }

    fn server_with_psk(identity: &str, key: &[u8]) -> TacacsPlusServer {
        let mut server = server_template();
        server.client_identity = Some(TlsClientClientIdentity {
            credentials_reference: None,
            certificate: None,
            tls13_epsk: Some(Tls13Epsk {
                external_identity: identity.to_owned(),
                hash: EpskSupportedHash::Sha256,
                context: None,
                target_protocol: None,
                target_kdf: None,
                psk_dhe_ke_groups: vec![],
                inline_definition: Some(SymmetricKeyInlineDefinition {
                    key_format: None,
                    cleartext_symmetric_key: Some(key.to_vec()),
                }),
            }),
        });
        server
    }

    fn server_with_psk_hash(hash: EpskSupportedHash) -> TacacsPlusServer {
        let mut server = server_with_psk("client-id", b"resolved-psk-bytes-with-enough-length");
        server
            .client_identity
            .as_mut()
            .expect("client identity")
            .tls13_epsk
            .as_mut()
            .expect("tls13 epsk")
            .hash = hash;
        server
    }

    fn server_with_psk_dhe_groups(groups: Vec<PskDheKeSupportedGroup>) -> TacacsPlusServer {
        let mut server = server_with_psk("client-id", b"resolved-psk-bytes-with-enough-length");
        server
            .client_identity
            .as_mut()
            .expect("client identity")
            .tls13_epsk
            .as_mut()
            .expect("tls13 epsk")
            .psk_dhe_ke_groups = groups;
        server
    }

    fn epsk(server: &TacacsPlusServer) -> &Tls13Epsk {
        tls13_epsk(server).expect("tls13 epsk")
    }

    #[test]
    fn server_has_psk_returns_true_when_tls13_epsk_present() {
        let server = server_with_psk("client-id", &[0u8; 16]);
        assert!(server_has_psk(&server));
    }

    #[test]
    fn server_has_psk_returns_false_without_client_identity() {
        let server = server_template();
        assert!(!server_has_psk(&server));
    }

    #[test]
    fn tls13_epsk_extracts_config_model() {
        let key = b"resolved-psk-bytes-with-enough-length";
        let server = server_with_psk("my-client", key);
        let epsk = epsk(&server);

        assert_eq!(epsk.external_identity, "my-client");
        assert_eq!(super::super::tls13_epsk::symmetric_key(epsk).expect("symmetric key"), key);
    }

    #[test]
    fn psk_dhe_ke_groups_preserves_psk_only_when_absent() {
        let server = server_with_psk("my-client", b"resolved-psk-bytes-with-enough-length");

        assert_eq!(PskDheKeGroups::from_config(&epsk(&server).psk_dhe_ke_groups), None);
    }

    #[test]
    fn psk_dhe_ke_groups_maps_config_order_to_openssl_names() {
        let server = server_with_psk_dhe_groups(vec![
            PskDheKeSupportedGroup::X25519,
            PskDheKeSupportedGroup::Secp256r1,
            PskDheKeSupportedGroup::Ffdhe3072,
        ]);
        let groups = PskDheKeGroups::from_config(&epsk(&server).psk_dhe_ke_groups)
            .expect("groups should be configured");

        assert_eq!(groups.as_openssl_list(), "X25519:P-256:ffdhe3072");
    }

    #[test]
    fn psk_handshake_hash_maps_sha256_to_sha256_ciphersuite() {
        let server = server_with_psk_hash(EpskSupportedHash::Sha256);
        let handshake_hash = PskHandshakeHash::from_config(epsk(&server).hash);

        assert_eq!(handshake_hash, PskHandshakeHash::Sha256);
        assert_eq!(handshake_hash.tls13_ciphersuites(), "TLS_AES_128_GCM_SHA256");
    }

    #[test]
    fn psk_handshake_hash_maps_sha384_to_sha384_ciphersuite() {
        let server = server_with_psk_hash(EpskSupportedHash::Sha384);
        let handshake_hash = PskHandshakeHash::from_config(epsk(&server).hash);

        assert_eq!(handshake_hash, PskHandshakeHash::Sha384);
        assert_eq!(handshake_hash.tls13_ciphersuites(), "TLS_AES_256_GCM_SHA384");
    }

    #[test]
    fn create_psk_ssl_context_accepts_supported_psk_dhe_groups() {
        let server = server_with_psk("client-id", b"resolved-psk-bytes-with-enough-length");
        let groups = PskDheKeGroups::from_config(&[
            PskDheKeSupportedGroup::X25519,
            PskDheKeSupportedGroup::Secp256r1,
        ])
        .expect("configured groups");

        create_psk_ssl_context(epsk(&server), Some(&groups))
            .expect("OpenSSL should accept supported TLS 1.3 groups");
    }

    #[test]
    fn create_psk_ssl_context_accepts_sha384() {
        let server = server_with_psk_hash(EpskSupportedHash::Sha384);

        create_psk_ssl_context(epsk(&server), None)
            .expect("OpenSSL should accept TLS 1.3 SHA-384 PSK sessions");
    }

    #[test]
    fn create_psk_ssl_context_accepts_all_supported_hashes() {
        for hash in EpskSupportedHash::ALL {
            let server = server_with_psk_hash(*hash);
            let handshake_hash = PskHandshakeHash::from_config(*hash);

            create_psk_ssl_context(epsk(&server), None).unwrap_or_else(|error| {
                panic!(
                    "OpenSSL should accept TLS 1.3 PSK hash {} using ciphersuite {}: {error:#}",
                    handshake_hash.as_name(),
                    handshake_hash.tls13_ciphersuites()
                )
            });
        }
    }

    #[test]
    fn create_psk_ssl_context_accepts_all_supported_psk_dhe_groups() {
        let server = server_with_psk("client-id", b"resolved-psk-bytes-with-enough-length");
        let groups =
            PskDheKeGroups::from_config(PskDheKeSupportedGroup::ALL).expect("configured groups");

        create_psk_ssl_context(epsk(&server), Some(&groups)).unwrap_or_else(|error| {
            panic!(
                "OpenSSL should accept every configured TLS 1.3 PSK-DHE group ({}): {error:#}",
                groups.as_openssl_list()
            )
        });
    }

    #[test]
    fn prepare_psk_client_config_surfaces_context_errors_before_handshake() {
        let server = server_with_psk("client-id", b"too-short");

        let Err(error) = PskClientConfig::prepare(epsk(&server)) else {
            panic!("invalid PSK credentials should be rejected during preparation");
        };
        let message = format!("{error:#}");

        assert!(message.contains("Failed to prepare OpenSSL TLS 1.3 PSK context"));
        assert!(message.contains("PSK key must be at least 16 bytes"));
    }

    #[test]
    fn create_psk_ssl_context_errors_for_unsupported_group_list() {
        let server = server_with_psk("client-id", b"resolved-psk-bytes-with-enough-length");
        let groups = PskDheKeGroups {
            openssl_list: "not-a-supported-tls-group".to_owned(),
        };

        let error = create_psk_ssl_context(epsk(&server), Some(&groups))
            .expect_err("unsupported OpenSSL group should be rejected");
        let message = error.to_string();

        assert!(message.contains("unsupported TLS PSK DHE group list"));
        assert!(message.contains("not-a-supported-tls-group"));
    }

    #[test]
    fn tls13_epsk_errors_when_missing() {
        let server = server_template();
        assert!(tls13_epsk(&server).is_err());
    }
}
