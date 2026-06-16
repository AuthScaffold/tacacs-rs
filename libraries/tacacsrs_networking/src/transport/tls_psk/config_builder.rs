//! Prepared TLS 1.3 PSK client configuration.
//!
//! The PSK transport prepares and validates its OpenSSL context before the
//! async handshake begins. That keeps configuration errors separate from
//! per-connection handshake failures and gives callers sharper diagnostics.

use anyhow::{Context, Result};
use openssl::ssl::Ssl;
use openssl::ssl::SslContext;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::{PskDheKeGroups, PskHandshakeHash, PskIdentity, create_psk_ssl_context};

pub(crate) struct PskClientConfig {
    handshake_hash: PskHandshakeHash,
    identity: String,
    psk_dhe_ke_groups: Option<PskDheKeGroups>,
    ssl_context: SslContext,
}

impl PskClientConfig {
    /// Prepares an OpenSSL TLS 1.3 PSK client context for the supplied PSK.
    pub(crate) fn prepare(
        psk: PskIdentity,
        handshake_hash: PskHandshakeHash,
        psk_dhe_ke_groups: Option<PskDheKeGroups>,
    ) -> Result<Self> {
        let identity = psk.identity().to_owned();
        let ssl_context = create_psk_ssl_context(&psk, handshake_hash, psk_dhe_ke_groups.as_ref())
            .with_context(|| {
                format!(
                    "Failed to prepare OpenSSL TLS 1.3 PSK context (identity: {identity}, hash: {}, groups: {})",
                    handshake_hash.as_name(),
                    format_groups(psk_dhe_ke_groups.as_ref())
                )
            })?;

        Ok(Self {
            handshake_hash,
            identity,
            psk_dhe_ke_groups,
            ssl_context,
        })
    }

    /// Establishes a TLS 1.3 PSK connection over the provided TCP stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the OpenSSL `SslContext` or `Ssl` object cannot be
    /// created, or if the TLS handshake fails.
    pub(crate) async fn connect(
        self,
        address: &str,
        stream: TcpStream,
    ) -> Result<SslStream<TcpStream>> {
        let ssl = Ssl::new(&self.ssl_context).with_context(|| {
            format!(
                "OpenSSL failed to allocate TLS 1.3 PSK SSL object for {address} (identity: {}, hash: {})",
                self.identity,
                self.handshake_hash.as_name()
            )
        })?;
        let mut tls_stream = SslStream::new(ssl, stream).with_context(|| {
            format!(
                "OpenSSL failed to attach TLS 1.3 PSK SSL object to TCP stream for {address} (identity: {})",
                self.identity
            )
        })?;

        tokio_openssl::SslStream::connect(std::pin::Pin::new(&mut tls_stream))
            .await
            .with_context(|| {
                format!(
                    "OpenSSL TLS 1.3 PSK handshake failed for {address} (identity: {}, hash: {}, groups: {})",
                    self.identity,
                    self.handshake_hash.as_name(),
                    format_groups(self.psk_dhe_ke_groups.as_ref())
                )
            })?;

        log::info!(
            target: module_path!(),
            "TLS 1.3 PSK connection established (address: {address}, identity: {}, hash: {}, groups: {})",
            self.identity,
            self.handshake_hash.as_name(),
            format_groups(self.psk_dhe_ke_groups.as_ref())
        );

        Ok(tls_stream)
    }
}

fn format_groups(groups: Option<&PskDheKeGroups>) -> &str {
    groups.map_or("psk-only", PskDheKeGroups::as_openssl_list)
}
