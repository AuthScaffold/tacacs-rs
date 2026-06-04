//! Build TLS 1.3 PSK connections directly from a [`TacacsPlusServer`]
//! configuration.
//!
//! This module owns the translation from the YANG-derived configuration model
//! to the lower-level PSK primitives ([`PskIdentity`], the symmetric key
//! bytes). It exists so the establishment dispatcher does not need to
//! understand PSK encoding details.

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use tacacsrs_config::{PskDheKeSupportedGroup, TacacsPlusServer};

use super::{PskConfigurationBuilder, PskIdentity};

/// OpenSSL TLS 1.3 group list derived from `psk-dhe-ke-groups`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PskDheKeGroups {
    openssl_list: String,
}

impl PskDheKeGroups {
    fn from_config(groups: &[PskDheKeSupportedGroup]) -> Option<Self> {
        if groups.is_empty() {
            return None;
        }

        Some(Self {
            openssl_list: groups
                .iter()
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

fn openssl_group_name(group: &PskDheKeSupportedGroup) -> &'static str {
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
    let psk = build_psk_identity(server).context("Invalid PSK credentials")?;
    let psk_dhe_ke_groups = build_psk_dhe_ke_groups(server);

    log::debug!("Negotiating TLS-PSK handshake with {address}");

    let tls_stream = PskConfigurationBuilder::new(psk)
        .with_psk_dhe_ke_groups(psk_dhe_ke_groups)
        .connect(tcp_stream)
        .await
        .inspect_err(|e| log::warn!("TLS-PSK handshake with {address} failed: {e:#}"))
        .context("Failed to establish TLS PSK connection")?;

    log::debug!("TLS-PSK connection to {address} ready");
    Ok(tls_stream)
}

/// Decodes the configured PSK identity and key bytes into a [`PskIdentity`].
fn build_psk_identity(server: &TacacsPlusServer) -> Result<PskIdentity> {
    let epsk = server
        .client_identity
        .as_ref()
        .and_then(|ci| ci.tls13_epsk.as_ref())
        .ok_or_else(|| anyhow::anyhow!("server has no TLS 1.3 PSK client-identity"))?;

    let key_bytes = epsk
        .inline_definition
        .as_ref()
        .and_then(|d| d.cleartext_symmetric_key.as_deref())
        .map(parse_symmetric_key_data)
        .unwrap_or_default();

    PskIdentity::new(&epsk.external_identity, key_bytes)
}

fn build_psk_dhe_ke_groups(server: &TacacsPlusServer) -> Option<PskDheKeGroups> {
    server
        .client_identity
        .as_ref()
        .and_then(|ci| ci.tls13_epsk.as_ref())
        .and_then(|epsk| PskDheKeGroups::from_config(&epsk.psk_dhe_ke_groups))
}

/// Decodes the YANG-encoded symmetric key bytes into raw key material.
///
/// The current YANG model carries the key as already-decoded bytes, so this is
/// a passthrough today — but it is the documented seam for future encoding
/// changes (e.g. base64 unwrapping).
fn parse_symmetric_key_data(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tls_psk::create_psk_ssl_context;
    use tacacsrs_config::generated::tacacs_plus::{Tls13Epsk, TlsClientClientIdentity};
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
                hash: tacacsrs_config::generated::tacacs_plus::EpskSupportedHash::Sha256,
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
    fn build_psk_identity_extracts_identity_and_key() {
        let key = b"resolved-psk-bytes-with-enough-length";
        let server = server_with_psk("my-client", key);
        let psk = build_psk_identity(&server).expect("PSK credentials should be valid");

        assert_eq!(psk.identity(), "my-client");
        assert_eq!(psk.key(), key.as_slice());
    }

    #[test]
    fn build_psk_dhe_ke_groups_preserves_psk_only_when_absent() {
        let server = server_with_psk("my-client", b"resolved-psk-bytes-with-enough-length");

        assert_eq!(build_psk_dhe_ke_groups(&server), None);
    }

    #[test]
    fn build_psk_dhe_ke_groups_maps_config_order_to_openssl_names() {
        let server = server_with_psk_dhe_groups(vec![
            PskDheKeSupportedGroup::X25519,
            PskDheKeSupportedGroup::Secp256r1,
            PskDheKeSupportedGroup::Ffdhe3072,
        ]);
        let groups = build_psk_dhe_ke_groups(&server).expect("groups should be configured");

        assert_eq!(groups.as_openssl_list(), "X25519:P-256:ffdhe3072");
    }

    #[test]
    fn create_psk_ssl_context_accepts_supported_psk_dhe_groups() {
        let psk = PskIdentity::new("client-id", b"resolved-psk-bytes-with-enough-length")
            .expect("valid psk");
        let groups = PskDheKeGroups::from_config(&[
            PskDheKeSupportedGroup::X25519,
            PskDheKeSupportedGroup::Secp256r1,
        ])
        .expect("configured groups");

        create_psk_ssl_context(&psk, None, Some(&groups))
            .expect("OpenSSL should accept supported TLS 1.3 groups");
    }

    #[test]
    fn create_psk_ssl_context_errors_for_unsupported_group_list() {
        let psk = PskIdentity::new("client-id", b"resolved-psk-bytes-with-enough-length")
            .expect("valid psk");
        let groups = PskDheKeGroups {
            openssl_list: "not-a-supported-tls-group".to_owned(),
        };

        let error = create_psk_ssl_context(&psk, None, Some(&groups))
            .expect_err("unsupported OpenSSL group should be rejected");
        let message = error.to_string();

        assert!(message.contains("unsupported TLS PSK DHE group list"));
        assert!(message.contains("not-a-supported-tls-group"));
    }

    #[test]
    fn build_psk_identity_errors_when_missing() {
        let server = server_template();
        assert!(build_psk_identity(&server).is_err());
    }

    #[test]
    fn parse_symmetric_key_data_bytes() {
        let key = parse_symmetric_key_data(b"resolved-psk-bytes");
        assert_eq!(key, b"resolved-psk-bytes");
    }
}
