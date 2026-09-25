//! TLS transport for TACACS+ connections.
//!
//! [`prepare_from_server`] interprets a [`TacacsPlusServer`] once.
//! The resulting context supports repeated TLS handshakes without reparsing
//! configuration. Callers use the dispatcher in [`crate::establish`].
//!
//! [`TacacsPlusServer`]: tacacsrs_config::TacacsPlusServer

mod config_builder;
mod from_server;
#[allow(clippy::module_inception)]
mod tls;

pub(crate) use config_builder::TlsConfigurationBuilder;
pub(crate) use from_server::{prepare_from_server, TlsClientConfig};

use anyhow::Context;
use openssl::ssl::Ssl;
use openssl::ssl::SslContext;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

/// Establishes a TLS connection over an existing TCP connection.
///
/// # Arguments
///
/// * `config` - The TLS client configuration.
/// * `stream` - The underlying TCP connection.
/// * `server_name` - The domain name or IP address for SNI, such as
///   `server.example.com` or `192.168.1.1`.
///
/// # Errors
///
/// Returns an error if:
/// - the server name is not a valid domain name or IP address, or
/// - the TLS handshake fails.
pub(crate) async fn connect_tls(
    context: &SslContext,
    stream: TcpStream,
    server_name: &str,
) -> anyhow::Result<SslStream<TcpStream>> {
    let mut ssl = Ssl::new(context).context("OpenSSL failed to allocate TLS SSL object")?;
    ssl.set_hostname(server_name)
        .with_context(|| format!("OpenSSL failed to set TLS SNI for {server_name}"))?;

    let mut stream = SslStream::new(ssl, stream)
        .context("OpenSSL failed to attach the TLS SSL object to the TCP connection")?;

    SslStream::connect(std::pin::Pin::new(&mut stream))
        .await
        .context("OpenSSL TLS handshake failed")?;

    Ok(stream)
}
