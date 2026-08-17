//! Builds TLS 1.3 PSK connections directly from [`TacacsPlusServer`]
//! configuration.

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt, Tls13Epsk};

use super::PskClientConfig;

/// Returns `true` when `server` has a TLS 1.3 PSK client identity. The dispatcher
/// uses this result to select the PSK transport.
#[must_use]
pub(crate) fn server_has_psk(server: &TacacsPlusServer) -> bool {
    server
        .client_identity
        .as_ref()
        .is_some_and(|ci| ci.tls13_epsk.is_some())
}

/// Establishes a TLS 1.3 PSK connection over an existing TCP connection using the
/// PSK material carried in `server`.
///
/// The PSK identity is taken from `client-identity.tls13-epsk.external-identity`
/// and the symmetric key from
/// `client-identity.tls13-epsk.inline-definition.cleartext-symmetric-key`.
///
/// # Errors
///
/// Returns an error if the configured PSK material is invalid. Examples include
/// an empty key and an identity that contains a NUL byte. The function also
/// returns an error if the TLS-PSK handshake fails. Before calling this function,
/// make sure that [`server_has_psk`] returns `true`. Without PSK configuration,
/// the function returns an error.
pub(crate) async fn establish_from_server(
    server: std::sync::Arc<TacacsPlusServer>,
    address: &str,
    tcp_stream: TcpStream,
) -> Result<SslStream<TcpStream>> {
    tls13_epsk(&server)?;
    let server_name = derive_sni_name(&server)?.map(str::to_owned);

    log::debug!(
        "Starting TLS-PSK handshake with {address} (SNI: {})",
        server_name.as_deref().unwrap_or("disabled")
    );

    let tls_stream = PskClientConfig::prepare(server)
        .context("Invalid OpenSSL TLS-PSK configuration")?
        .connect(address, server_name.as_deref(), tcp_stream)
        .await
        .inspect_err(|e| log::warn!("TLS-PSK handshake with {address} failed: {e:#}"))
        .context("Failed to establish TLS-PSK connection")?;

    log::debug!("TLS-PSK connection to {address} ready");
    Ok(tls_stream)
}

fn tls13_epsk(server: &TacacsPlusServer) -> Result<&Tls13Epsk> {
    server
        .client_identity
        .as_ref()
        .and_then(|ci| ci.tls13_epsk.as_ref())
        .ok_or_else(|| anyhow::anyhow!("Server has no TLS 1.3 PSK client identity"))
}

fn derive_sni_name(server: &TacacsPlusServer) -> Result<Option<&str>> {
    if !server.sni_enabled() {
        return Ok(None);
    }

    server
        .domain_name
        .as_deref()
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("sni-enabled requires domain-name"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacacsrs_config::generated::tacacs_plus::{
        EpskSupportedHash, Tls13Epsk, TlsClientClientIdentity,
    };
    use tacacsrs_config::keystore::SymmetricKeyInlineDefinition;
    use tacacsrs_secrets::SecretBytes;

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
                    cleartext_symmetric_key: Some(SecretBytes::new(key.to_vec())),
                }),
                central_keystore_reference: None,
            }),
        });
        server
    }

    fn epsk(server: &TacacsPlusServer) -> &Tls13Epsk {
        tls13_epsk(server).expect("server must have TLS 1.3 EPSK configuration")
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
        assert_eq!(super::super::tls13_epsk::symmetric_key(&server).expect("symmetric key"), key);
    }

    #[test]
    fn tls13_epsk_errors_when_missing() {
        let server = server_template();
        assert!(tls13_epsk(&server).is_err());
    }

    #[test]
    fn derive_sni_name_returns_none_when_sni_disabled() {
        let server = server_with_psk("client-id", &[0u8; 16]);

        assert_eq!(derive_sni_name(&server).expect("SNI derivation must succeed"), None);
    }

    #[test]
    fn derive_sni_name_uses_domain_when_sni_enabled() {
        let mut server = server_with_psk("client-id", &[0u8; 16]);
        server.sni_enabled = Some(true);
        server.domain_name = Some("tacacs.example.com".to_owned());

        assert_eq!(
            derive_sni_name(&server).expect("SNI derivation must succeed"),
            Some("tacacs.example.com")
        );
    }

    #[test]
    fn derive_sni_name_errors_when_enabled_without_domain() {
        let mut server = server_with_psk("client-id", &[0u8; 16]);
        server.sni_enabled = Some(true);

        let error = derive_sni_name(&server).expect_err("a missing SNI domain must fail");

        assert!(error
            .to_string()
            .contains("sni-enabled requires domain-name"));
    }
}
