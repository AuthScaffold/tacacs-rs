//! Centralised stream establishment from a [`TacacsPlusServer`] configuration.
//!
//! This module bridges the configuration model and the transport layer,
//! providing a single function that handles TCP,
//! TLS (certificate-based), and TLS-PSK connection setup. It replaces the
//! duplicated connection logic that previously lived in both `tacon` and
//! `tacacsrs_agent`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tacacsrs_config::crypto_types::PrivateKeyFormat;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tokio_rustls::rustls;

use crate::BoxedTransport;
use crate::helpers::{connect_tcp, tls_server_name};
use crate::transport::tls::TlsConfigurationBuilder;

/// Options that control connection behaviour beyond what the
/// [`TacacsPlusServer`] already carries.
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Dangerously disable TLS certificate verification.
    pub disable_certificate_verification: bool,
    /// Connection timeout. When `None`, no timeout is applied to the TCP
    /// connect phase — callers are responsible for their own timeouts.
    pub timeout: Option<Duration>,
}

/// Establishes a transport stream to the server described by `server`.
///
/// The transport type is selected based on the resolved server configuration:
///
/// | Configuration | Transport |
/// |---------------|-----------|
/// | `client-identity.tls13-epsk` | TLS 1.3 PSK (feature-gated) |
/// | `client-identity.certificate` or `server-authentication` | mTLS / TLS |
/// | `shared-secret` only | Plain TCP |
///
/// CA certificates from `server-authentication.ca-certs` and `ee-certs` are
/// loaded into the TLS root store when present. The SNI server name is derived
/// from `domain-name` when `sni-enabled` is set, falling back to the socket
/// address.
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection fails or times out
/// - TLS certificate/key material cannot be parsed
/// - TLS handshake fails
pub async fn establish_stream(
    server: &TacacsPlusServer,
    options: &ConnectOptions,
) -> Result<BoxedTransport> {
    let address = server.socket_address();

    let security_label = if server.is_tls() {
        "tls"
    } else {
        "obfuscation"
    };
    log::debug!(
        "Connecting to TACACS+ server {address} (security: {security_label}, timeout: {:?})",
        options.timeout,
    );

    let tcp_stream = match options.timeout {
        Some(dur) => tokio::time::timeout(dur, connect_tcp(&address))
            .await
            .with_context(|| format!("Timed out connecting to {address}"))?
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?,
        None => connect_tcp(&address)
            .await
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?,
    };

    log::debug!("TCP connection to {address} established");

    // --- TLS-PSK (must be checked before general TLS) ---
    #[cfg(feature = "psk")]
    if let Some(ref ci) = server.client_identity {
        if let Some(ref epsk) = ci.tls13_epsk {
            log::debug!("Negotiating TLS-PSK handshake with {address}");

            let key_material = epsk
                .inline_definition
                .as_ref()
                .and_then(|d| d.cleartext_symmetric_key.as_deref())
                .unwrap_or_default();
            let key_bytes = parse_symmetric_key_data(key_material);

            let psk =
                crate::transport::tls_psk::PskIdentity::new(&epsk.external_identity, key_bytes)
                    .context("Invalid PSK credentials")?;

            let tls_stream = crate::transport::tls_psk::PskConfigurationBuilder::new(psk)
                .connect(tcp_stream)
                .await
                .inspect_err(|e| log::warn!("TLS-PSK handshake with {address} failed: {e:#}"))
                .context("Failed to establish TLS PSK connection")?;

            log::debug!("TLS-PSK connection to {address} ready");
            return Ok(BoxedTransport::new(tls_stream));
        }
    }

    // --- Certificate-based TLS ---
    if server.is_tls() {
        let tls_stream = establish_cert_tls_stream(server, &address, options, tcp_stream).await?;
        Ok(BoxedTransport::new(tls_stream))
    } else {
        // Plain TCP (obfuscation mode)
        Ok(BoxedTransport::new(tcp_stream))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Establishes a certificate-based TLS connection.
async fn establish_cert_tls_stream(
    server: &TacacsPlusServer,
    address: &str,
    options: &ConnectOptions,
    tcp_stream: tokio::net::TcpStream,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let sni_name = derive_sni_name(server, address);
    log::debug!("Negotiating TLS handshake with {address} (SNI: {sni_name})");

    let mut builder = TlsConfigurationBuilder::new();

    // Load custom CA certificates into the root store
    if let Some(ref root_store) = build_root_cert_store(server)? {
        builder = builder.with_root_certificates(root_store.clone());
    }

    // Load client certificate if present
    if let Some(ref ci) = server.client_identity {
        if let Some(ref cert) = ci.certificate {
            if let Some(ref inline) = cert.inline_definition {
                if let (Some(cert_data), Some(key_data)) =
                    (&inline.cert_data, &inline.cleartext_private_key)
                {
                    let certs = parse_certificate_data(cert_data)
                        .inspect_err(|e| {
                            log::warn!("Failed to parse TLS certificate for {address}: {e:#}");
                        })
                        .context("Failed to parse TLS certificate")?;

                    let key = parse_private_key_data(key_data, inline.private_key_format.as_ref())
                        .inspect_err(|e| {
                            log::warn!("Failed to parse TLS private key for {address}: {e:#}");
                        })
                        .context("Failed to parse TLS private key")?;

                    builder = builder.with_client_auth_der(certs, key);
                }
            }
        }
    }

    if options.disable_certificate_verification {
        builder = builder.with_certificate_verification_disabled(true);
    }

    let tls_config = Arc::new(
        builder
            .build()
            .inspect_err(|e| log::warn!("Failed to build TLS config for {address}: {e:#}"))
            .context("Failed to build TLS configuration")?,
    );

    let tls_stream = crate::transport::tls::connect_tls(&tls_config, tcp_stream, sni_name)
        .await
        .inspect_err(|e| log::warn!("TLS handshake with {address} failed: {e:#}"))
        .context("Failed to establish TLS connection")?;

    log::debug!("TLS connection to {address} ready");
    Ok(tls_stream)
}

/// Derives the TLS server name (for SNI and verification) from the server
/// configuration. When `sni-enabled` is true and `domain-name` is set, the
/// domain name is used; otherwise falls back to extracting the host from the
/// socket address.
fn derive_sni_name<'a>(server: &'a TacacsPlusServer, address: &'a str) -> &'a str {
    if server.sni_enabled() {
        if let Some(ref domain) = server.domain_name {
            return domain.as_str();
        }
    }
    tls_server_name(address)
}

/// Builds a custom [`rustls::RootCertStore`] from the server's `ca-certs` and
/// `ee-certs` inline definitions. Returns `None` if no custom CA material
/// is configured (the builder will use the default webpki roots).
fn build_root_cert_store(server: &TacacsPlusServer) -> Result<Option<rustls::RootCertStore>> {
    let Some(ref sa) = server.server_authentication else {
        return Ok(None);
    };

    let mut has_certs = false;
    let mut root_store = rustls::RootCertStore::empty();

    // Load CA certificates
    if let Some(ref ca) = sa.ca_certs {
        if let Some(ref inline) = ca.inline_definition {
            for cert_entry in &inline.certificate {
                add_cert_to_store(&cert_entry.cert_data, &mut root_store).with_context(|| {
                    format!("failed to parse CA certificate '{}'", cert_entry.name)
                })?;
                has_certs = true;
            }
        }
    }

    // Load EE (end-entity) certificates
    if let Some(ref ee) = sa.ee_certs {
        if let Some(ref inline) = ee.inline_definition {
            for cert_entry in &inline.certificate {
                add_cert_to_store(&cert_entry.cert_data, &mut root_store).with_context(|| {
                    format!("failed to parse EE certificate '{}'", cert_entry.name)
                })?;
                has_certs = true;
            }
        }
    }

    if has_certs {
        Ok(Some(root_store))
    } else {
        Ok(None)
    }
}

/// Adds a DER-encoded certificate to a root cert store.
fn add_cert_to_store(cert_data: &[u8], store: &mut rustls::RootCertStore) -> Result<()> {
    let certs = parse_certificate_data(cert_data)?;
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("failed to add certificate to root store: {e}"))?;
    }
    Ok(())
}

/// Parses DER-encoded certificate data.
fn parse_certificate_data(data: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    if data.is_empty() {
        anyhow::bail!("certificate DER data is empty");
    }

    if crate::helpers::data_contains_pem_header(data) {
        anyhow::bail!("PEM-encoded certificates are not supported; provide DER bytes");
    }

    Ok(vec![CertificateDer::from(data.to_vec())])
}

/// Parses DER-encoded private key data using the YANG `private-key-format`
/// identity when available. When no format is specified, PKCS#8 DER is used.
///
/// Format mapping (RFC 9640 / `ietf-crypto-types`):
/// - `rsa-private-key-format`  → PKCS#1 `RSAPrivateKey` DER
/// - `ec-private-key-format`   → SEC1 `ECPrivateKey` DER
/// - `one-asymmetric-key-format` → PKCS#8 `OneAsymmetricKey` DER
fn parse_private_key_data(
    data: &[u8],
    private_key_format: Option<&PrivateKeyFormat>,
) -> Result<PrivateKeyDer<'static>> {
    if data.is_empty() {
        anyhow::bail!("private key DER data is empty");
    }

    if crate::helpers::data_contains_pem_header(data) {
        anyhow::bail!("PEM-encoded private keys are not supported; provide DER bytes");
    }

    if let Some(fmt) = private_key_format {
        let der_bytes = data.to_vec();

        return match fmt {
            PrivateKeyFormat::RsaPrivateKeyFormat => {
                Ok(PrivateKeyDer::Pkcs1(rustls_pki_types::PrivatePkcs1KeyDer::from(der_bytes)))
            }
            PrivateKeyFormat::EcPrivateKeyFormat => {
                Ok(PrivateKeyDer::Sec1(rustls_pki_types::PrivateSec1KeyDer::from(der_bytes)))
            }
            PrivateKeyFormat::OneAsymmetricKeyFormat => {
                Ok(PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(der_bytes)))
            }
        };
    }

    Ok(PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(data.to_vec())))
}

#[cfg(feature = "psk")]
fn parse_symmetric_key_data(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_sni_name_uses_domain_when_sni_enabled() {
        let server = tacacsrs_config::TacacsPlusServer {
            name: "test".to_owned(),
            server_type: tacacsrs_config::TacacsPlusServerType::all(),
            address: "10.0.0.1".to_owned(),
            port: 49,
            shared_secret: None,
            timeout: 5,
            single_connection: false,
            domain_name: Some("tacacs.example.com".to_owned()),
            sni_enabled: Some(true),
            client_identity: None,
            server_authentication: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        };

        assert_eq!(derive_sni_name(&server, "10.0.0.1:49"), "tacacs.example.com");
    }

    #[test]
    fn derive_sni_name_falls_back_to_address_when_sni_disabled() {
        let server = tacacsrs_config::TacacsPlusServer {
            name: "test".to_owned(),
            server_type: tacacsrs_config::TacacsPlusServerType::all(),
            address: "10.0.0.1".to_owned(),
            port: 49,
            shared_secret: None,
            timeout: 5,
            single_connection: false,
            domain_name: Some("tacacs.example.com".to_owned()),
            sni_enabled: None,
            client_identity: None,
            server_authentication: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        };

        assert_eq!(derive_sni_name(&server, "10.0.0.1:49"), "10.0.0.1");
    }

    #[test]
    fn parse_certificate_data_der_bytes() {
        let der = b"\x30\x82\x01\x00fake-der-cert-data";
        let result = parse_certificate_data(der);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_certificate_data_rejects_pem() {
        let result = parse_certificate_data(b"-----BEGIN CERTIFICATE-----\n...");

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PEM-encoded certificates are not supported; provide DER bytes",
        );
    }

    #[test]
    fn parse_certificate_data_rejects_pem_after_leading_noise() {
        let result = parse_certificate_data(b"\n\t \xEF\xBB\xBF-----BEGIN CERTIFICATE-----\n...");

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PEM-encoded certificates are not supported; provide DER bytes",
        );
    }

    #[test]
    fn parse_private_key_data_rejects_pem() {
        let result = parse_private_key_data(b"-----BEGIN PRIVATE KEY-----\n...", None);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PEM-encoded private keys are not supported; provide DER bytes",
        );
    }

    #[test]
    fn parse_private_key_data_rejects_pem_after_leading_noise() {
        let result =
            parse_private_key_data(b"\n\t \xEF\xBB\xBF-----BEGIN PRIVATE KEY-----\n...", None);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "PEM-encoded private keys are not supported; provide DER bytes",
        );
    }

    #[cfg(feature = "psk")]
    #[test]
    fn parse_symmetric_key_data_bytes() {
        let key = parse_symmetric_key_data(b"resolved-psk-bytes");

        assert_eq!(key, b"resolved-psk-bytes");
    }
}
