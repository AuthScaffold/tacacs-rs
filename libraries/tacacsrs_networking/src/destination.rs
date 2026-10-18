//! TACACS+ server destination resolution and TCP connection setup.
//!
//! This module resolves a configured host name to socket addresses off the
//! runtime worker threads, then connects to the first reachable destination. An
//! optional [`ConnectionGuard`] checks each destination before connect and the
//! connected socket before any TLS or TACACS+ traffic.

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
    let mut last_error = None;
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
                    target: "tacacsrs_networking::destination::connect_tcp",
                    "Connected to TACACS+ server {server_address}");
                return Ok(stream);
            }
            Err(e) => {
                log::error!(
                    target: "tacacsrs_networking::destination::connect_tcp",
                    "Failed to connect to TACACS+ server {server_address}: {e}");
                last_error = Some(e);
            }
        }
    }

    match last_error {
        Some(error) => Err(error).context("Failed to connect to any TACACS+ server address"),
        None => Err(anyhow::Error::msg("Failed to connect to any TACACS+ server address")),
    }
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

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn all_failed_addresses_preserve_last_native_error() {
        use super::connect_after_resolution;

        let failed_address = "127.0.0.1:0".parse().unwrap();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            connect_after_resolution(std::future::ready(Ok(vec![failed_address])), None),
        )
        .await
        .expect("the invalid native destination must finish")
        .unwrap_err();

        assert_eq!(error.to_string(), "Failed to connect to any TACACS+ server address");
        assert!(error
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some()));
    }

    #[tokio::test]
    async fn failed_address_does_not_prevent_later_success() {
        use super::connect_after_resolution;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listening_address = listener.local_addr().unwrap();
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            connect_after_resolution(
                std::future::ready(Ok(vec!["127.0.0.1:0".parse().unwrap(), listening_address])),
                None,
            ),
        )
        .await
        .expect("the available native destination must finish")
        .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), listening_address);
    }

    #[tokio::test]
    async fn empty_resolution_has_no_native_error_cause() {
        use super::{SocketAddr, connect_after_resolution};

        let error =
            connect_after_resolution(std::future::ready(Ok(Vec::<SocketAddr>::new())), None)
                .await
                .unwrap_err();

        assert_eq!(error.to_string(), "Failed to connect to any TACACS+ server address");
        assert!(!error
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some()));
    }

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
}
