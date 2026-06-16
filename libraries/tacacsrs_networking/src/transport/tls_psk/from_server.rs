//! Build TLS 1.3 PSK connections directly from a [`TacacsPlusServer`]
//! configuration.

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use tacacsrs_config::{TacacsPlusServer, Tls13Epsk};

use super::PskClientConfig;

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
    fn tls13_epsk_errors_when_missing() {
        let server = server_template();
        assert!(tls13_epsk(&server).is_err());
    }
}
