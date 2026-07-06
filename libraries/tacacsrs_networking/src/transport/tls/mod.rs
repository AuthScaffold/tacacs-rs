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
mod from_server;
#[allow(clippy::module_inception)]
mod tls;

pub(crate) use config_builder::TlsConfigurationBuilder;
pub(crate) use from_server::establish_from_server;

use anyhow::Context;
use openssl::ssl::Ssl;
use openssl::ssl::SslContext;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

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
    context: &SslContext,
    stream: TcpStream,
    server_name: &str,
) -> anyhow::Result<SslStream<TcpStream>> {
    let mut ssl = Ssl::new(context).context("OpenSSL failed to allocate TLS SSL object")?;
    ssl.set_hostname(server_name)
        .with_context(|| format!("OpenSSL failed to set TLS SNI for {server_name}"))?;

    let mut stream = SslStream::new(ssl, stream)
        .context("OpenSSL failed to attach TLS SSL object to TCP stream")?;

    SslStream::connect(std::pin::Pin::new(&mut stream))
        .await
        .context("OpenSSL TLS handshake failed")?;

    Ok(stream)
}
