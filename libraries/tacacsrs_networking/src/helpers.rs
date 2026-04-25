//! Helper functions for TACACS+ networking.
//!
//! This module provides utilities for TCP connection handling and address resolution.

use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::Context;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tacacsrs_config::crypto_types::PrivateKeyFormat;
use tokio_rustls::rustls;

/// Resolves a hostname (with optional port) to a list of socket addresses.
///
/// If no port is specified, the default TACACS+ port (49) is used.
///
/// # Arguments
///
/// * `hostname` - The hostname, optionally with port (e.g., "server.example.com" or "server.example.com:49")
///
/// # Errors
///
/// Returns an error if DNS resolution fails.
pub fn get_server_addresses(hostname: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let address = if hostname.contains(':') {
        hostname.to_string()
    } else {
        format!("{}:{}", hostname, 49)
    };

    let server_address_list: Vec<SocketAddr> = address.to_socket_addrs()?.collect();
    Ok(server_address_list)
}

/// Establishes a TCP connection to a TACACS+ server.
///
/// Attempts to connect to each resolved address in order until one succeeds.
///
/// # Arguments
///
/// * `hostname` - The server hostname, optionally with port
///
/// # Errors
///
/// Returns an error if connection fails to all resolved addresses.
pub async fn connect_tcp(hostname: &str) -> anyhow::Result<tokio::net::TcpStream> {
    for server_address in get_server_addresses(hostname)? {
        match tokio::net::TcpStream::connect(server_address).await {
            Ok(stream) => {
                log::info!(
                    target: "tacacsrs_networking::helpers::connect_tcp",
                    "Connected to server: {server_address}");
                return Ok(stream);
            }
            Err(e) => {
                log::error!(
                    target: "tacacsrs_networking::helpers::connect_tcp",
                    "Failed to connect to server {server_address}: {e}");
            }
        }
    }

    Err(anyhow::Error::msg("Failed to connect to any server"))
}

/// Extracts the TLS server name from a configured `host[:port]` address string.
///
/// This accepts plain hostnames, IPv4 `host:port`, and bracketed IPv6
/// `[addr]:port` formats and returns just the host portion that should be used
/// for SNI and certificate name checks.
#[must_use]
pub fn tls_server_name(server_addr: &str) -> &str {
    if let Some(stripped) = server_addr
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
    {
        return stripped;
    }

    // Only attempt host:port splitting when exactly one colon is present.
    // Any valid IPv6 literal contains ≥2 colons, so this guard ensures
    // unbracketed IPv6 addresses are never misinterpreted as host:port.
    if server_addr.matches(':').count() == 1 {
        if let Some((host, port)) = server_addr.rsplit_once(':') {
            if port.parse::<u16>().is_ok() {
                return host;
            }
        }
    }

    server_addr
}

/// Returns the default web PKI root certificate store used for outbound TLS
/// client verification.
#[must_use]
pub fn default_root_cert_store() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Returns whether `data` contains a PEM block marker.
#[must_use]
pub(crate) fn data_contains_pem_header(data: &[u8]) -> bool {
    const PEM_HEADER: &[u8] = b"-----BEGIN";

    data.windows(PEM_HEADER.len())
        .any(|window| window == PEM_HEADER)
}

/// Normalizes CLI-supplied client certificate bytes to DER.
///
/// PEM input is decoded to a single DER certificate. DER input is passed
/// through unchanged. This helper is intentionally for CLI/runtime file inputs;
/// YANG-backed config data remains DER-only.
///
/// # Errors
///
/// Returns an error if the input is empty, the PEM data is malformed, or the
/// PEM file contains anything other than exactly one certificate.
pub fn normalize_cli_certificate_data(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.is_empty() {
        anyhow::bail!("client certificate data is empty");
    }

    if !data_contains_pem_header(data) {
        return Ok(data.to_vec());
    }

    let certificates = CertificateDer::pem_slice_iter(data)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse PEM client certificate")?;

    if certificates.len() != 1 {
        anyhow::bail!("client certificate file must contain exactly one PEM certificate");
    }

    Ok(certificates[0].as_ref().to_vec())
}

/// Normalizes CLI-supplied client private key bytes to DER and reports its format.
///
/// PEM input is decoded using `rustls_pki_types`. DER input is inspected to
/// determine whether it is PKCS#1, SEC1, or PKCS#8 so the resulting
/// `tacacsrs-config` inline definition can preserve the correct key format.
/// This helper is intentionally for CLI/runtime file inputs only.
///
/// # Errors
///
/// Returns an error if the input is empty, the PEM data is malformed, or the
/// DER bytes do not describe a supported private key format.
pub fn normalize_cli_private_key_data(data: &[u8]) -> anyhow::Result<(Vec<u8>, PrivateKeyFormat)> {
    if data.is_empty() {
        anyhow::bail!("client private key data is empty");
    }

    let private_key = if data_contains_pem_header(data) {
        PrivateKeyDer::from_pem_slice(data).context("failed to parse PEM client private key")?
    } else {
        PrivateKeyDer::try_from(data).map_err(|_| {
            anyhow::anyhow!(
                "unsupported DER client private key format; expected PKCS#1, SEC1, or PKCS#8"
            )
        })?
    };

    let private_key_format = match &private_key {
        PrivateKeyDer::Pkcs1(_) => PrivateKeyFormat::RsaPrivateKeyFormat,
        PrivateKeyDer::Sec1(_) => PrivateKeyFormat::EcPrivateKeyFormat,
        PrivateKeyDer::Pkcs8(_) => PrivateKeyFormat::OneAsymmetricKeyFormat,
        _ => anyhow::bail!("unsupported client private key format"),
    };

    Ok((private_key.secret_der().to_vec(), private_key_format))
}

/// Parses a `host:port` string into its host and port components.
///
/// Supports these formats:
/// - `host:port` — IPv4 or hostname with explicit port
/// - `host` — bare hostname, uses `default_port`
/// - `[ipv6]:port` — bracketed IPv6 with explicit port
/// - `[ipv6]` — bracketed IPv6, uses `default_port`
/// - `ipv6` — unbracketed IPv6 literal (≥2 colons), uses `default_port`
#[must_use]
pub fn parse_host_port(addr: &str, default_port: u16) -> (String, u16) {
    // Bracketed IPv6: [addr] or [addr]:port
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, after_bracket)) = rest.split_once(']') {
            let port = after_bracket
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (host.to_owned(), port);
        }
    }

    // Only attempt host:port splitting when exactly one colon is present.
    // Any valid IPv6 literal contains ≥2 colons, so this guard ensures
    // unbracketed IPv6 addresses are never misinterpreted as host:port.
    if addr.matches(':').count() == 1 {
        if let Some((host, port_str)) = addr.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return (host.to_owned(), port);
            }
        }
    }

    (addr.to_owned(), default_port)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tacacsrs_config::crypto_types::PrivateKeyFormat;

    use super::{
        data_contains_pem_header, default_root_cert_store, normalize_cli_certificate_data,
        normalize_cli_private_key_data, parse_host_port, tls_server_name,
    };

    fn sample_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("samples")
            .join(file_name)
    }

    #[test]
    fn test_tls_server_name_plain_hostname() {
        assert_eq!(tls_server_name("example.com"), "example.com");
    }

    #[test]
    fn test_tls_server_name_ipv4_with_port() {
        assert_eq!(tls_server_name("192.0.2.10:49"), "192.0.2.10");
    }

    #[test]
    fn test_tls_server_name_ipv6_with_port() {
        assert_eq!(tls_server_name("[2001:db8::1]:49"), "2001:db8::1");
    }

    #[test]
    fn test_tls_server_name_unbracketed_ipv6_literal_is_unchanged() {
        assert_eq!(tls_server_name("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn test_tls_server_name_unbracketed_ipv6_localhost_is_unchanged() {
        assert_eq!(tls_server_name("::1"), "::1");
    }

    #[test]
    fn test_tls_server_name_unbracketed_ipv6_full_is_unchanged() {
        assert_eq!(
            tls_server_name("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        );
    }

    #[test]
    fn test_tls_server_name_bracketed_ipv6_without_port() {
        assert_eq!(tls_server_name("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn test_tls_server_name_hostname_with_port() {
        assert_eq!(tls_server_name("tacacs.example.com:49"), "tacacs.example.com");
    }

    #[test]
    fn test_tls_server_name_hostname_with_non_numeric_port_is_unchanged() {
        assert_eq!(tls_server_name("host:notaport"), "host:notaport");
    }

    #[test]
    fn test_default_root_cert_store_is_not_empty() {
        let root_store = default_root_cert_store();
        assert!(!root_store.is_empty());
    }

    #[test]
    fn test_data_contains_pem_header_accepts_plain_pem() {
        assert!(data_contains_pem_header(b"-----BEGIN CERTIFICATE-----\n..."));
    }

    #[test]
    fn test_data_contains_pem_header_finds_marker_after_leading_noise() {
        assert!(data_contains_pem_header(b"\n\t \xEF\xBB\xBF-----BEGIN PRIVATE KEY-----\n..."));
    }

    #[test]
    fn test_data_contains_pem_header_rejects_der_and_empty_data() {
        assert!(!data_contains_pem_header(b"\x30\x82\x01\x00fake-der"));
        assert!(!data_contains_pem_header(b"\n\t "));
    }

    #[test]
    fn normalize_cli_certificate_data_accepts_pem() {
        let pem_bytes = fs::read(sample_path("client.crt")).expect("sample cert exists");
        let der_bytes = fs::read(sample_path("client.crt.der")).expect("sample DER cert exists");

        let normalized =
            normalize_cli_certificate_data(&pem_bytes).expect("PEM client cert should parse");

        assert_eq!(normalized, der_bytes);
    }

    #[test]
    fn normalize_cli_private_key_data_accepts_pem() {
        let pem_bytes = fs::read(sample_path("client.key")).expect("sample key exists");
        let der_bytes = fs::read(sample_path("client.key.der")).expect("sample DER key exists");

        let (normalized, format) =
            normalize_cli_private_key_data(&pem_bytes).expect("PEM client key should parse");

        assert_eq!(normalized, der_bytes);
        assert_eq!(format, PrivateKeyFormat::OneAsymmetricKeyFormat);
    }

    #[test]
    fn normalize_cli_private_key_data_detects_der_format() {
        let der_bytes = fs::read(sample_path("client.key.der")).expect("sample DER key exists");

        let (normalized, format) =
            normalize_cli_private_key_data(&der_bytes).expect("DER client key should parse");

        assert_eq!(normalized, der_bytes);
        assert_eq!(format, PrivateKeyFormat::OneAsymmetricKeyFormat);
    }

    #[test]
    fn test_parse_host_port_plain_hostname() {
        assert_eq!(parse_host_port("example.com", 49), ("example.com".to_owned(), 49));
    }

    #[test]
    fn test_parse_host_port_hostname_with_port() {
        assert_eq!(parse_host_port("example.com:8080", 49), ("example.com".to_owned(), 8080));
    }

    #[test]
    fn test_parse_host_port_ipv4_with_port() {
        assert_eq!(parse_host_port("192.0.2.10:49", 49), ("192.0.2.10".to_owned(), 49));
    }

    #[test]
    fn test_parse_host_port_ipv4_without_port() {
        assert_eq!(parse_host_port("192.0.2.10", 49), ("192.0.2.10".to_owned(), 49));
    }

    #[test]
    fn test_parse_host_port_bracketed_ipv6_with_port() {
        assert_eq!(parse_host_port("[2001:db8::1]:49", 49), ("2001:db8::1".to_owned(), 49),);
    }

    #[test]
    fn test_parse_host_port_bracketed_ipv6_without_port() {
        assert_eq!(parse_host_port("[2001:db8::1]", 49), ("2001:db8::1".to_owned(), 49),);
    }

    #[test]
    fn test_parse_host_port_unbracketed_ipv6() {
        assert_eq!(parse_host_port("2001:db8::1", 49), ("2001:db8::1".to_owned(), 49),);
    }

    #[test]
    fn test_parse_host_port_ipv6_localhost() {
        assert_eq!(parse_host_port("::1", 49), ("::1".to_owned(), 49));
    }

    #[test]
    fn test_parse_host_port_non_numeric_port_treated_as_bare_host() {
        assert_eq!(parse_host_port("host:notaport", 49), ("host:notaport".to_owned(), 49),);
    }
}
