//! TLS transport for TACACS+ connections.
//!
//! Connections are constructed exclusively through
//! [`establish_from_server`], which interprets a [`TacacsPlusServer`]
//! configuration and performs the TLS handshake. The internal
//! `TlsConfigurationBuilder` and `connect_tls` helpers are no longer part
//! of the public API; callers should drive the dispatcher in
//! [`crate::establish`] instead.
//!
//! [`TacacsPlusServer`]: tacacsrs_config::TacacsPlusServer

mod config_builder;
mod danger;
mod from_server;
#[allow(clippy::module_inception)]
mod tls;

pub(crate) use config_builder::TlsConfigurationBuilder;
pub(crate) use from_server::establish_from_server;

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
pub(crate) async fn connect_tls(
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
