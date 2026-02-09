//! Builder for TLS 1.3 PSK client configurations.

use openssl::ssl::Ssl;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::{PskIdentity, create_psk_ssl_context};

/// A builder for creating TLS 1.3 PSK client connections.
///
/// Provides a fluent API for configuring PSK-based TLS connections with options
/// for SNI (Server Name Indication) and cipher suite selection.
///
/// # Example
///
/// ```no_run
/// use tacacsrs_networking::tls_psk::{PskIdentity, PskConfigurationBuilder};
/// use tacacsrs_networking::helpers::connect_tcp;
///
/// # async fn example() -> anyhow::Result<()> {
/// let psk = PskIdentity::new("client1", b"shared_key");
///
/// let tcp_stream = connect_tcp("tacacs.example.com:49").await?;
/// let tls_stream = PskConfigurationBuilder::new(psk)
///     .with_server_name("tacacs.example.com")
///     .connect(tcp_stream)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct PskConfigurationBuilder {
    psk: PskIdentity,
    server_name: Option<String>,
    ciphersuites: Option<String>,
}

impl PskConfigurationBuilder {
    /// Creates a new `PskConfigurationBuilder` with the given PSK identity.
    ///
    /// # Arguments
    ///
    /// * `psk` - The pre-shared key identity and secret to use for authentication
    pub fn new(psk: PskIdentity) -> Self {
        Self {
            psk,
            server_name: None,
            ciphersuites: None,
        }
    }

    /// Sets the server name for SNI (Server Name Indication).
    ///
    /// While PSK doesn't require SNI for authentication, some servers may
    /// expect it for routing or configuration purposes.
    ///
    /// # Arguments
    ///
    /// * `server_name` - The server hostname for SNI
    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = Some(server_name.into());
        self
    }

    /// Sets custom TLS 1.3 cipher suites.
    ///
    /// The default cipher suites are `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`.
    ///
    /// # Arguments
    ///
    /// * `ciphersuites` - Colon-separated list of TLS 1.3 cipher suite names
    pub fn with_ciphersuites(mut self, ciphersuites: impl Into<String>) -> Self {
        self.ciphersuites = Some(ciphersuites.into());
        self
    }

    /// Establishes a TLS 1.3 PSK connection over the provided TCP stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - The underlying TCP stream to wrap with TLS
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The OpenSSL SSL context cannot be created
    /// - The SSL object cannot be created
    /// - The TLS handshake fails
    pub async fn connect(self, stream: TcpStream) -> anyhow::Result<SslStream<TcpStream>> {
        let ssl_context = create_psk_ssl_context(&self.psk)?;

        let mut ssl = Ssl::new(&ssl_context)?;

        // Set SNI if configured
        if let Some(ref server_name) = self.server_name {
            ssl.set_hostname(server_name)?;
        }

        let mut tls_stream = SslStream::new(ssl, stream)?;

        tokio_openssl::SslStream::connect(std::pin::Pin::new(&mut tls_stream)).await?;

        log::info!(
            target: "tacacsrs_networking::tls_psk",
            "TLS 1.3 PSK connection established (identity: {})",
            self.psk.identity()
        );

        Ok(tls_stream)
    }
}
