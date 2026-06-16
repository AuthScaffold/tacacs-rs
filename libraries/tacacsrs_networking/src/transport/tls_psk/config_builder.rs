//! Prepared TLS 1.3 PSK client configuration.
//!
//! The PSK transport prepares and validates its OpenSSL context before the
//! async handshake begins. That keeps configuration errors separate from
//! per-connection handshake failures and gives callers sharper diagnostics.

use anyhow::{Context, Result};
use openssl::ssl::Ssl;
use openssl::ssl::SslContext;
use tacacsrs_config::generated::tacacs_plus::Tls13Epsk;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::{PskDheKeGroups, PskHandshakeHash, create_psk_ssl_context};

pub(crate) struct PskClientConfig {
    handshake_hash: PskHandshakeHash,
    psk_dhe_ke_groups: Option<PskDheKeGroups>,
    ssl_context: SslContext,
}

impl PskClientConfig {
    /// Prepares an OpenSSL TLS 1.3 PSK client context for the supplied EPSK config.
    pub(crate) fn prepare(epsk: &Tls13Epsk) -> Result<Self> {
        let handshake_hash = PskHandshakeHash::from_config(epsk.hash);
        let psk_dhe_ke_groups = PskDheKeGroups::from_config(&epsk.psk_dhe_ke_groups);
        let ssl_context = create_psk_ssl_context(epsk, psk_dhe_ke_groups.as_ref())
            .with_context(|| {
                format!(
                    "Failed to prepare OpenSSL TLS 1.3 PSK context (identity: {}, hash: {}, groups: {})",
                    epsk.external_identity,
                    handshake_hash.as_name(),
                    format_groups(psk_dhe_ke_groups.as_ref())
                )
            })?;

        Ok(Self {
            handshake_hash,
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
        let identity = super::tls13_psk_session::configured_tls13_epsk(&self.ssl_context)
            .map_or("<unknown>", |epsk| epsk.external_identity.as_str());
        let ssl = Ssl::new(&self.ssl_context).with_context(|| {
            format!(
                "OpenSSL failed to allocate TLS 1.3 PSK SSL object for {address} (identity: {}, hash: {})",
                identity,
                self.handshake_hash.as_name()
            )
        })?;
        let mut tls_stream = SslStream::new(ssl, stream).with_context(|| {
            format!(
                "OpenSSL failed to attach TLS 1.3 PSK SSL object to TCP stream for {address} (identity: {identity})"
            )
        })?;

        tokio_openssl::SslStream::connect(std::pin::Pin::new(&mut tls_stream))
            .await
            .with_context(|| {
                format!(
                    "OpenSSL TLS 1.3 PSK handshake failed for {address} (identity: {}, hash: {}, groups: {})",
                    identity,
                    self.handshake_hash.as_name(),
                    format_groups(self.psk_dhe_ke_groups.as_ref())
                )
            })?;

        log::info!(
            target: module_path!(),
            "TLS 1.3 PSK connection established (address: {address}, identity: {}, hash: {}, groups: {})",
            identity,
            self.handshake_hash.as_name(),
            format_groups(self.psk_dhe_ke_groups.as_ref())
        );

        Ok(tls_stream)
    }
}

fn format_groups(groups: Option<&PskDheKeGroups>) -> &str {
    groups.map_or("psk-only", PskDheKeGroups::as_openssl_list)
}
