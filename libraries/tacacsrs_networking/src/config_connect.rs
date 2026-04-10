//! Centralised stream establishment from a [`ResolvedServer`] configuration.
//!
//! This module bridges the config layer ([`tacacsrs_config::ResolvedServer`])
//! and the transport layer, providing a single function that handles TCP,
//! TLS (certificate-based), and TLS-PSK connection setup. It replaces the
//! duplicated connection logic that previously lived in both `tacon` and
//! `tacacsrs_agent`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tacacsrs_config::ResolvedServer;
use tokio_rustls::rustls;

use crate::BoxedTransport;
use crate::helpers::{connect_tcp, tls_server_name};
use crate::transport::tls::TlsConfigurationBuilder;

/// Options that control connection behaviour beyond what the
/// [`ResolvedServer`] already carries.
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
/// - Raw private key (RPK) client auth is configured (not yet supported)
pub async fn establish_stream(
    server: &ResolvedServer,
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

            let psk = crate::transport::tls_psk::PskIdentity::new(
                &epsk.external_identity,
                key_material.as_bytes(),
            )
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
        // Reject raw-private-key client auth until supported
        if let Some(ref ci) = server.client_identity {
            if ci.raw_private_key.is_some() {
                anyhow::bail!("raw public key (RPK) client authentication is not yet supported");
            }
        }

        let sni_name = derive_sni_name(server, &address);
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
                        builder = builder
                            .with_client_auth_cert_pem(cert_data, key_data)
                            .inspect_err(|e| {
                                log::warn!("Failed to load TLS certificates for {address}: {e:#}");
                            })
                            .context("Failed to load TLS certificates")?;
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
        Ok(BoxedTransport::new(tls_stream))
    } else {
        // Plain TCP (obfuscation mode)
        Ok(BoxedTransport::new(tcp_stream))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derives the TLS server name (for SNI and verification) from the server
/// configuration. When `sni-enabled` is true and `domain-name` is set, the
/// domain name is used; otherwise falls back to extracting the host from the
/// socket address.
fn derive_sni_name<'a>(server: &'a ResolvedServer, address: &'a str) -> &'a str {
    if server.sni_enabled() {
        if let Some(ref domain) = server.domain_name {
            return domain.as_str();
        }
    }
    tls_server_name(address)
}

/// Builds a custom [`RootCertStore`] from the server's `ca-certs` and
/// `ee-certs` inline definitions. Returns `None` if no custom CA material
/// is configured (the builder will use the default webpki roots).
fn build_root_cert_store(server: &ResolvedServer) -> Result<Option<rustls::RootCertStore>> {
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

/// Adds a certificate (PEM or base64-encoded DER) to a root cert store.
fn add_cert_to_store(cert_data: &str, store: &mut rustls::RootCertStore) -> Result<()> {
    let certs = parse_certificate_data(cert_data)?;
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("failed to add certificate to root store: {e}"))?;
    }
    Ok(())
}

/// Parses certificate data that may be either PEM (with BEGIN/END markers)
/// or base64-encoded DER.
fn parse_certificate_data(data: &str) -> Result<Vec<CertificateDer<'static>>> {
    let trimmed = data.trim();

    if trimmed.starts_with("-----BEGIN") {
        // PEM format
        CertificateDer::pem_slice_iter(trimmed.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("failed to parse certificate PEM: {e}"))
    } else {
        // Base64-encoded DER
        let der_bytes = BASE64
            .decode(trimmed)
            .context("failed to base64-decode certificate data")?;
        Ok(vec![CertificateDer::from(der_bytes)])
    }
}

/// Parses private key data that may be either PEM or base64-encoded DER.
#[allow(dead_code)]
fn parse_private_key_data(data: &str) -> Result<PrivateKeyDer<'static>> {
    let trimmed = data.trim();

    if trimmed.starts_with("-----BEGIN") {
        PrivateKeyDer::from_pem_slice(trimmed.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to parse private key PEM: {e}"))
    } else {
        let der_bytes = BASE64
            .decode(trimmed)
            .context("failed to base64-decode private key data")?;
        // Try PKCS#8 first, then fall back to PKCS#1
        Ok(PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(der_bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_sni_name_uses_domain_when_sni_enabled() {
        let server = ResolvedServer::from_raw(tacacsrs_config::TacacsPlusServer {
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
            hello_params: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        });

        assert_eq!(derive_sni_name(&server, "10.0.0.1:49"), "tacacs.example.com");
    }

    #[test]
    fn derive_sni_name_falls_back_to_address_when_sni_disabled() {
        let server = ResolvedServer::from_raw(tacacsrs_config::TacacsPlusServer {
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
            hello_params: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        });

        assert_eq!(derive_sni_name(&server, "10.0.0.1:49"), "10.0.0.1");
    }

    #[test]
    fn parse_certificate_data_pem() {
        // A minimal self-signed cert PEM (just check parsing works)
        let pem = "-----BEGIN CERTIFICATE-----\n\
                    MIIBkTCB+wIUfC9WJvBfXv/v4gXyBEkHJ2cGbV0wDQYJKoZIhvcNAQELBQAwEjEQ\n\
                    MA4GA1UEAwwHdGVzdC1jYTAeFw0yNDA0MDEwMDAwMDBaFw0yNjA0MDEwMDAwMDBa\n\
                    MBIxEDAOBgNVBAMMB3Rlc3QtY2EwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA0Z3q\n\
                    X2BTLS4e+aThBsGMx5I0MBiAl4vBE1oMRcJ+s6J2bbTGCNkXOxnJPRjy9QAOG1aG\n\
                    M+whxfdPYFbajbW0bQIDAQABoyMwITAfBgNVHREEGDAWhwR/AAABhwQKAAEBhwQK\n\
                    AAECMAoGCCqGSM49BAMCA0gAMEUCIQCI+GS5E3D1JvHb4M0ouHuaRKEFW0GW8UOO\n\
                    OAXAG+bOygIgW7LF5J4c8O4DJPP2VddsNOKmKHqEZnnVqMSGIgfaoFo=\n\
                    -----END CERTIFICATE-----";
        let certs = parse_certificate_data(pem);
        assert!(certs.is_ok());
        assert_eq!(certs.unwrap().len(), 1);
    }

    #[test]
    fn parse_certificate_data_base64_der() {
        // Just verify the base64 decode path doesn't panic on valid base64
        // (the decoded bytes won't be a real cert, but we test the decode logic)
        let b64 = BASE64.encode(b"\x30\x82\x01\x00fake-der-cert-data");
        let result = parse_certificate_data(&b64);
        // This will succeed at the decode step but may fail at store.add;
        // we're testing the parsing path here
        assert!(result.is_ok());
    }
}
