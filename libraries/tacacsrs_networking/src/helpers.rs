//! Helper functions for TACACS+ networking.
//!
//! This module provides utilities for TCP connection handling and address resolution.

use std::net::{SocketAddr, ToSocketAddrs};

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
                    "Connected to server: {}", server_address);
                return Ok(stream);
            }
            Err(e) => {
                log::error!(
                    target: "tacacsrs_networking::helpers::connect_tcp",
                    "Failed to connect to server {}: {}", server_address, e);
                continue;
            }
        };
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
    rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

#[cfg(test)]
mod tests {
    use super::{default_root_cert_store, tls_server_name};

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
    fn test_default_root_cert_store_is_not_empty() {
        let root_store = default_root_cert_store();
        assert!(!root_store.is_empty());
    }
}
