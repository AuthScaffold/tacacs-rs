//! Internal builder for TLS 1.3 PSK client configurations.
//!
//! This type is intentionally **not** part of the public API: all callers
//! must drive PSK connection construction through
//! [`crate::config_connect::establish_stream`], which guarantees that the
//! YANG configuration model is the single source of truth for transport
//! parameters.

use openssl::ssl::Ssl;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::{PskDheKeGroups, PskIdentity, create_psk_ssl_context};

pub(crate) struct PskConfigurationBuilder {
    psk: PskIdentity,
    psk_dhe_ke_groups: Option<PskDheKeGroups>,
}

impl PskConfigurationBuilder {
    /// Creates a new builder for the given PSK identity.
    pub(crate) const fn new(psk: PskIdentity) -> Self {
        Self {
            psk,
            psk_dhe_ke_groups: None,
        }
    }

    /// Enables TLS 1.3 `psk_dhe_ke` by configuring OpenSSL key-share groups.
    pub(crate) fn with_psk_dhe_ke_groups(mut self, groups: Option<PskDheKeGroups>) -> Self {
        self.psk_dhe_ke_groups = groups;
        self
    }

    /// Establishes a TLS 1.3 PSK connection over the provided TCP stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the OpenSSL `SslContext` or `Ssl` object cannot be
    /// created, or if the TLS handshake fails.
    pub(crate) async fn connect(self, stream: TcpStream) -> anyhow::Result<SslStream<TcpStream>> {
        let ssl_context = create_psk_ssl_context(&self.psk, None, self.psk_dhe_ke_groups.as_ref())?;

        let ssl = Ssl::new(&ssl_context)?;
        let mut tls_stream = SslStream::new(ssl, stream)?;

        tokio_openssl::SslStream::connect(std::pin::Pin::new(&mut tls_stream)).await?;

        log::info!(
            target: module_path!(),
            "TLS 1.3 PSK connection established (identity: {})",
            self.psk.identity()
        );

        Ok(tls_stream)
    }
}
