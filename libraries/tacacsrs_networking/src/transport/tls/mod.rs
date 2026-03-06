//! TLS configuration and transport utilities for TACACS+ connections.
//!
//! This module provides:
//! - [`TlsConfigurationBuilder`] - A builder for creating TLS client configurations
//! - [`connect_tls`] - A helper function for establishing TLS connections
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use tacacsrs_networking::transport::tls::{TlsConfigurationBuilder, connect_tls};
//! use tacacsrs_networking::helpers::connect_tcp;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = Arc::new(TlsConfigurationBuilder::new().build()?);
//! let tcp_stream = connect_tcp("tacacs.example.com:49").await?;
//! let tls_stream = connect_tls(&config, tcp_stream, "tacacs.example.com").await?;
//! # Ok(())
//! # }
//! ```

mod config_builder;
mod danger;
#[allow(clippy::module_inception)]
mod tls;

pub use config_builder::TlsConfigurationBuilder;

use std::net::IpAddr;
use std::sync::Arc;
use tokio_rustls::{rustls, TlsConnector};

/// Establishes a TLS connection over an existing TCP stream.
///
/// # Arguments
///
/// * `config` - The TLS client configuration
/// * `stream` - The underlying TCP stream
/// * `server_name` - The server name for SNI - can be a domain name (e.g., "server.example.com")
///   or an IP address (e.g., "192.168.1.1")
///
/// # Errors
///
/// Returns an error if:
/// - The server name is neither a valid domain name nor IP address
/// - The TLS handshake fails
pub async fn connect_tls(
    config: &Arc<rustls::ClientConfig>,
    stream: tokio::net::TcpStream,
    server_name: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let connector = TlsConnector::from(config.clone());

    // Try parsing as IP address first, then fall back to DNS name
    let server_name = if let Ok(ip) = server_name.parse::<IpAddr>() {
        rustls::pki_types::ServerName::IpAddress(ip.into())
    } else {
        rustls::pki_types::ServerName::try_from(server_name)
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name")
            })?
            .to_owned()
    };

    let stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream> =
        connector.connect(server_name, stream).await?;
    Ok(stream)
}
