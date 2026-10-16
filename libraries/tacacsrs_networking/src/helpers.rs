//! Helper functions for TACACS+ networking.
//!
//! This module resolves server addresses and opens TCP connections.

use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::Context as _;
use crate::endpoint::ConnectionGuard;

/// Resolves a host name and optional port to a list of socket addresses.
///
/// If no port is specified, the default TACACS+ port (49) is used.
///
/// # Arguments
///
/// * `hostname` - The host name and optional port, such as
///   `server.example.com` or `server.example.com:49`.
///
/// # Errors
///
/// Returns an error if DNS resolution fails.
pub(crate) fn get_server_addresses(hostname: &str) -> anyhow::Result<Vec<SocketAddr>> {
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
/// * `hostname` - The server host name and optional port.
///
/// # Errors
///
/// Returns an error if all connection attempts fail.
pub(crate) async fn connect_tcp(
    hostname: &str,
    guard: Option<&dyn ConnectionGuard>,
) -> anyhow::Result<tokio::net::TcpStream> {
    connect_after_resolution(resolve_server_addresses(hostname), guard).await
}

async fn connect_after_resolution(
    resolution: impl std::future::Future<Output = anyhow::Result<Vec<SocketAddr>>> + Send,
    guard: Option<&dyn ConnectionGuard>,
) -> anyhow::Result<tokio::net::TcpStream> {
    for server_address in resolution.await? {
        if let Some(guard) = guard {
            guard.check_destination(server_address)?;
        }
        match tokio::net::TcpStream::connect(server_address).await {
            Ok(stream) => {
                if let Some(guard) = guard {
                    guard.check_connected(
                        stream
                            .peer_addr()
                            .context("inspect connected TACACS+ peer")?,
                        stream
                            .local_addr()
                            .context("inspect connected TACACS+ local address")?,
                    )?;
                }
                log::info!(
                    target: "tacacsrs_networking::helpers::connect_tcp",
                    "Connected to TACACS+ server {server_address}");
                return Ok(stream);
            }
            Err(e) => {
                log::error!(
                    target: "tacacsrs_networking::helpers::connect_tcp",
                    "Failed to connect to TACACS+ server {server_address}: {e}");
            }
        }
    }

    Err(anyhow::Error::msg("Failed to connect to any TACACS+ server address"))
}

/// Resolves server addresses off the runtime threads.
///
/// `ToSocketAddrs` blocks, so resolving inline would stall every task sharing
/// the worker thread.
async fn resolve_server_addresses(hostname: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let hostname = hostname.to_owned();
    tokio::task::spawn_blocking(move || get_server_addresses(&hostname))
        .await
        .context("The TACACS+ address resolution task failed")?
}

/// Returns whether `data` contains a PEM block marker.
#[must_use]
pub(crate) fn data_contains_pem_header(data: &[u8]) -> bool {
    const PEM_HEADER: &[u8] = b"-----BEGIN";

    data.windows(PEM_HEADER.len())
        .any(|window| window == PEM_HEADER)
}

#[cfg(test)]
mod tests {
    use super::data_contains_pem_header;

    #[tokio::test]
    async fn changed_resolution_cannot_bypass_destination_guard() {
        use super::{ConnectionGuard, SocketAddr, connect_after_resolution};

        struct Exclude(SocketAddr);
        impl ConnectionGuard for Exclude {
            fn check_destination(&self, destination: SocketAddr) -> anyhow::Result<()> {
                anyhow::ensure!(destination != self.0, "excluded destination");
                Ok(())
            }
            fn check_connected(&self, peer: SocketAddr, _: SocketAddr) -> anyhow::Result<()> {
                self.check_destination(peer)
            }
        }
        let allowed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let excluded = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let guard = Exclude(excluded.local_addr().unwrap());
        let initial = async { Ok(vec![allowed.local_addr().unwrap()]) };
        drop(
            connect_after_resolution(initial, Some(&guard))
                .await
                .unwrap(),
        );
        let changed = async { Ok(vec![excluded.local_addr().unwrap()]) };
        assert!(connect_after_resolution(changed, Some(&guard))
            .await
            .is_err());
        assert!(tokio::time::timeout(std::time::Duration::from_millis(25), excluded.accept())
            .await
            .is_err());
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
}
