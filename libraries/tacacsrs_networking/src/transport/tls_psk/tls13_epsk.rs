//! Accessors and validation for YANG TLS 1.3 EPSK configuration.

use anyhow::{Result, bail};
use tacacsrs_config::generated::tacacs_plus::Tls13Epsk;
use tacacsrs_config::TacacsPlusServer;

/// The minimum required TLS 1.3 EPSK key length in bytes.
///
/// Per RFC 9257 section 6, PSKs must be at least 128 bits.
pub(crate) const MIN_PSK_KEY_LENGTH: usize = 16;

/// Returns the inline symmetric key configured for a TLS 1.3 EPSK.
pub(crate) fn config(server: &TacacsPlusServer) -> Result<&Tls13Epsk> {
    server
        .client_identity
        .as_ref()
        .and_then(|identity| identity.tls13_epsk.as_ref())
        .ok_or_else(|| anyhow::anyhow!("server has no TLS 1.3 PSK client identity"))
}

/// Returns resolved central or inline symmetric key bytes.
pub(crate) fn symmetric_key(server: &TacacsPlusServer) -> Result<&[u8]> {
    let secret = config(server)?
        .inline_definition
        .as_ref()
        .and_then(|definition| definition.cleartext_symmetric_key.as_ref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TLS 1.3 EPSK inline-definition.cleartext-symmetric-key must be configured"
            )
        })?;
    Ok(secret.expose_secret())
}

/// Validates the TLS 1.3 EPSK fields required by the OpenSSL PSK callback.
pub(crate) fn validate(server: &TacacsPlusServer) -> Result<()> {
    let epsk = config(server)?;
    if epsk.external_identity.is_empty() {
        bail!("PSK identity must not be empty");
    }

    if epsk.external_identity.contains('\0') {
        bail!(
            "PSK identity must not contain NUL bytes (identity is passed to OpenSSL as a byte string)"
        );
    }

    let key = symmetric_key(server)?;
    if key.len() < MIN_PSK_KEY_LENGTH {
        bail!(
            "PSK key must be at least {} bytes (128 bits), per RFC 9257 section 6; got {} bytes",
            MIN_PSK_KEY_LENGTH,
            key.len()
        );
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn test_server(epsk: Tls13Epsk) -> std::sync::Arc<TacacsPlusServer> {
    use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerType, TlsClientClientIdentity};

    let server = TacacsPlusServer {
        name: "test".to_owned(),
        server_type: TacacsPlusServerType::all(),
        address: "127.0.0.1".to_owned(),
        port: 449,
        shared_secret: None,
        timeout: 5,
        single_connection: false,
        domain_name: None,
        sni_enabled: None,
        client_identity: Some(TlsClientClientIdentity {
            credentials_reference: None,
            certificate: None,
            tls13_epsk: Some(epsk),
        }),
        server_authentication: None,
        source_ip: None,
        source_interface: None,
        vrf_instance: None,
    };
    std::sync::Arc::new(server)
}
