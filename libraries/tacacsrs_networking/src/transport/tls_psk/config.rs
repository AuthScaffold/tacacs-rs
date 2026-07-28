//! Prepared TLS 1.3 PSK client configuration.
//!
//! The PSK transport prepares and validates its OpenSSL context before the
//! async handshake begins. That keeps configuration errors separate from
//! per-connection handshake failures and gives callers sharper diagnostics.

use anyhow::{Context, Result};
use openssl::ssl::Ssl;
use openssl::ssl::SslContext;
use tacacsrs_config::generated::tacacs_plus::Tls13Epsk;
use tacacsrs_config::EpskSupportedHash;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::context::create_psk_ssl_context;
use super::PskDheKeGroups;

pub(crate) struct PskClientConfig {
    external_identity: String,
    handshake_hash: EpskSupportedHash,
    psk_dhe_ke_groups: Option<PskDheKeGroups>,
    ssl_context: SslContext,
}

impl PskClientConfig {
    /// Prepares an OpenSSL TLS 1.3 PSK client context for the supplied EPSK config.
    pub(crate) fn prepare(epsk: &Tls13Epsk) -> Result<Self> {
        let handshake_hash = epsk.hash;
        let psk_dhe_ke_groups = PskDheKeGroups::from_config(&epsk.psk_dhe_ke_groups);
        let ssl_context = create_psk_ssl_context(epsk, psk_dhe_ke_groups.as_ref())
            .with_context(|| {
                format!(
                    "Failed to prepare OpenSSL TLS 1.3 PSK context (identity: {}, hash: {}, groups: {})",
                    epsk.external_identity,
                    handshake_hash.as_rfc7951_str(),
                    format_groups(psk_dhe_ke_groups.as_ref())
                )
            })?;

        Ok(Self {
            external_identity: epsk.external_identity.clone(),
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
        server_name: Option<&str>,
        stream: TcpStream,
    ) -> Result<SslStream<TcpStream>> {
        let mut ssl = Ssl::new(&self.ssl_context).with_context(|| {
            format!(
                "OpenSSL failed to allocate TLS 1.3 PSK SSL object for {address} (identity: {}, hash: {})",
                self.external_identity,
                self.handshake_hash.as_rfc7951_str()
            )
        })?;

        if let Some(server_name) = server_name {
            ssl.set_hostname(server_name).with_context(|| {
                format!(
                    "OpenSSL failed to set TLS 1.3 PSK SNI for {address} (SNI: {server_name}, identity: {})",
                    self.external_identity
                )
            })?;
        }

        let mut tls_stream = SslStream::new(ssl, stream).with_context(|| {
            format!(
                "OpenSSL failed to attach TLS 1.3 PSK SSL object to TCP stream for {address} (identity: {})",
                self.external_identity
            )
        })?;

        tokio_openssl::SslStream::connect(std::pin::Pin::new(&mut tls_stream))
            .await
            .with_context(|| {
                format!(
                    "OpenSSL TLS 1.3 PSK handshake failed for {address} (identity: {}, hash: {}, groups: {})",
                    self.external_identity,
                    self.handshake_hash.as_rfc7951_str(),
                    format_groups(self.psk_dhe_ke_groups.as_ref())
                )
            })?;

        log::info!(
            target: module_path!(),
            "TLS 1.3 PSK connection established (address: {address}, identity: {}, hash: {}, groups: {})",
            self.external_identity,
            self.handshake_hash.as_rfc7951_str(),
            format_groups(self.psk_dhe_ke_groups.as_ref())
        );

        Ok(tls_stream)
    }
}

fn format_groups(groups: Option<&PskDheKeGroups>) -> &str {
    groups.map_or("psk-only", PskDheKeGroups::as_openssl_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacacsrs_config::generated::tacacs_plus::{EpskSupportedHash, Tls13Epsk};
    use tacacsrs_config::keystore::SymmetricKeyInlineDefinition;

    fn epsk_with_key(key: &[u8]) -> Tls13Epsk {
        Tls13Epsk {
            external_identity: "client-id".to_owned(),
            hash: EpskSupportedHash::Sha256,
            context: None,
            target_protocol: None,
            target_kdf: None,
            psk_dhe_ke_groups: vec![],
            inline_definition: Some(SymmetricKeyInlineDefinition {
                key_format: None,
                cleartext_symmetric_key: Some(key.to_vec()),
            }),
            central_keystore_reference: None,
        }
    }

    #[test]
    fn prepare_surfaces_context_errors_before_handshake() {
        let epsk = epsk_with_key(b"too-short");

        let Err(error) = PskClientConfig::prepare(&epsk) else {
            panic!("invalid PSK credentials should be rejected during preparation");
        };
        let message = format!("{error:#}");

        assert!(message.contains("Failed to prepare OpenSSL TLS 1.3 PSK context"));
        assert!(message.contains("PSK key must be at least 16 bytes"));
    }
}
