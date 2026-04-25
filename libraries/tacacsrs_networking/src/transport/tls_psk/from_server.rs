//! Build TLS 1.3 PSK connections directly from a [`TacacsPlusServer`]
//! configuration.
//!
//! This module owns the translation from the YANG-derived configuration model
//! to the lower-level PSK primitives ([`PskIdentity`], the symmetric key
//! bytes). It exists so the `config_connect` dispatcher does not need to
//! understand PSK encoding details.

use anyhow::{Context, Result};
use tacacsrs_config::TacacsPlusServer;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::{PskConfigurationBuilder, PskIdentity};

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

    log::debug!("Negotiating TLS-PSK handshake with {address}");

    let tls_stream = PskConfigurationBuilder::new(psk)
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
                inline_definition: Some(SymmetricKeyInlineDefinition {
                    key_format: None,
                    cleartext_symmetric_key: Some(key.to_vec()),
                }),
            }),
        });
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
