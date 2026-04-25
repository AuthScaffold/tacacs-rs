//! Build certificate-based TLS connections directly from a
//! [`TacacsPlusServer`] configuration.
//!
//! This module owns the translation from the YANG-derived configuration model
//! to the lower-level TLS primitives (`rustls::RootCertStore`, DER certificate
//! chains, `PrivateKeyDer`, SNI server names). It exists so the `config_connect`
//! dispatcher does not need to understand certificate or key encoding details.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tacacsrs_config::TacacsPlusServer;
use tacacsrs_config::TacacsPlusServerExt;
use tacacsrs_config::crypto_types::PrivateKeyFormat;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls;

use super::TlsConfigurationBuilder;
use super::connect_tls;
use crate::helpers::{data_contains_pem_header, tls_server_name};

/// Establishes a certificate-based TLS connection over an existing TCP stream
/// using the security parameters carried in `server`.
///
/// The TLS root store is populated from `server-authentication.ca-certs` and
/// `ee-certs` when present. Client authentication material is loaded from
/// `client-identity.certificate.inline-definition` when both `cert-data` and
/// `cleartext-private-key` are present. SNI is derived from `domain-name` when
/// `sni-enabled` is set, otherwise it falls back to the host portion of
/// `address`.
///
/// # Errors
///
/// Returns an error if any TLS material in the configuration cannot be parsed,
/// the resulting `rustls::ClientConfig` cannot be built, or the TLS handshake
/// fails.
pub async fn establish_from_server(
    server: &TacacsPlusServer,
    address: &str,
    tcp_stream: TcpStream,
    disable_certificate_verification: bool,
) -> Result<TlsStream<TcpStream>> {
    let sni_name = derive_sni_name(server, address);
    log::debug!("Negotiating TLS handshake with {address} (SNI: {sni_name})");

    let mut builder = TlsConfigurationBuilder::new();

    if let Some(root_store) = build_root_cert_store(server)? {
        builder = builder.with_root_certificates(root_store);
    }

    if let Some((cert_chain, key)) = extract_client_auth(server, address)? {
        builder = builder.with_client_auth_der(cert_chain, key);
    }

    if disable_certificate_verification {
        builder = builder.with_certificate_verification_disabled(true);
    }

    let tls_config = Arc::new(
        builder
            .build()
            .inspect_err(|e| log::warn!("Failed to build TLS config for {address}: {e:#}"))
            .context("Failed to build TLS configuration")?,
    );

    let tls_stream = connect_tls(&tls_config, tcp_stream, sni_name)
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
/// `ee-certs` inline definitions. Returns `Ok(None)` if no custom CA material
/// is configured (in which case the default web PKI roots will be used).
fn build_root_cert_store(server: &TacacsPlusServer) -> Result<Option<rustls::RootCertStore>> {
    let Some(ref sa) = server.server_authentication else {
        return Ok(None);
    };

    let mut has_certs = false;
    let mut root_store = rustls::RootCertStore::empty();

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

    Ok(has_certs.then_some(root_store))
}

/// Extracts the inline client certificate chain and private key from `server`
/// when both are present. Returns `Ok(None)` when no client authentication
/// material is configured.
fn extract_client_auth(
    server: &TacacsPlusServer,
    address: &str,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    let Some(ref ci) = server.client_identity else {
        return Ok(None);
    };
    let Some(ref cert) = ci.certificate else {
        return Ok(None);
    };
    let Some(ref inline) = cert.inline_definition else {
        return Ok(None);
    };
    let (Some(cert_data), Some(key_data)) = (&inline.cert_data, &inline.cleartext_private_key)
    else {
        return Ok(None);
    };

    let certs = parse_certificate_data(cert_data)
        .inspect_err(|e| log::warn!("Failed to parse TLS certificate for {address}: {e:#}"))
        .context("Failed to parse TLS certificate")?;
    let key = parse_private_key_data(key_data, inline.private_key_format.as_ref())
        .inspect_err(|e| log::warn!("Failed to parse TLS private key for {address}: {e:#}"))
        .context("Failed to parse TLS private key")?;

    Ok(Some((certs, key)))
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

    if data_contains_pem_header(data) {
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

    if data_contains_pem_header(data) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn server_template() -> TacacsPlusServer {
        TacacsPlusServer {
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
        }
    }

    #[test]
    fn derive_sni_name_uses_domain_when_sni_enabled() {
        let mut server = server_template();
        server.sni_enabled = Some(true);

        assert_eq!(derive_sni_name(&server, "10.0.0.1:49"), "tacacs.example.com");
    }

    #[test]
    fn derive_sni_name_falls_back_to_address_when_sni_disabled() {
        let server = server_template();

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

    #[test]
    fn build_root_cert_store_returns_none_without_server_authentication() {
        let server = server_template();
        let store = build_root_cert_store(&server).expect("no server-auth should be ok");
        assert!(store.is_none());
    }

    #[test]
    fn extract_client_auth_returns_none_without_client_identity() {
        let server = server_template();
        let auth = extract_client_auth(&server, "10.0.0.1:49").expect("no client-identity");
        assert!(auth.is_none());
    }
}
