//! Helper functions for TACACS+ networking.
//!
//! This module provides utilities for TCP connection handling and address resolution.

use std::net::{SocketAddr, ToSocketAddrs};

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
