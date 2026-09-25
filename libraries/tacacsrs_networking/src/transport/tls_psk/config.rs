//! Prepared TLS 1.3 PSK client configuration.
//!
//! The PSK transport prepares and validates its OpenSSL context before the
//! async handshake. This separates configuration errors from handshake errors.

use anyhow::{Context, Result};
use openssl::ssl::Ssl;
use openssl::ssl::SslContext;
use tacacsrs_config::TacacsPlusServer;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::context::create_psk_ssl_context;
use super::PskDheKeGroups;

#[derive(Clone)]
pub(crate) struct PskClientConfig {
    hash_name: &'static str,
    psk_dhe_ke_groups: Option<PskDheKeGroups>,
    ssl_context: SslContext,
}

impl PskClientConfig {
    /// Prepares an OpenSSL TLS 1.3 PSK client context from EPSK configuration.
    pub(crate) fn prepare(server: &TacacsPlusServer) -> Result<Self> {
        let epsk = super::tls13_epsk::config(server)?;
        let handshake_hash = epsk.hash;
        let psk_dhe_ke_groups = PskDheKeGroups::from_config(&epsk.psk_dhe_ke_groups);
        let ssl_context =
            create_psk_ssl_context(server, psk_dhe_ke_groups.as_ref()).with_context(|| {
                format!(
                    "Failed to prepare OpenSSL TLS 1.3 PSK context (hash: {}, groups: {})",
                    handshake_hash.as_rfc7951_str(),
                    format_groups(psk_dhe_ke_groups.as_ref())
                )
            })?;

        Ok(Self {
            hash_name: handshake_hash.as_rfc7951_str(),
            psk_dhe_ke_groups,
            ssl_context,
        })
    }

    /// Establishes a TLS 1.3 PSK connection over the provided TCP connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the OpenSSL `SslContext` or `Ssl` object cannot be
    /// created, or if the TLS handshake fails.
    pub(crate) async fn connect(
        &self,
        address: &str,
        server_name: Option<&str>,
        stream: TcpStream,
    ) -> Result<SslStream<TcpStream>> {
        let mut ssl = Ssl::new(&self.ssl_context).with_context(|| {
            format!(
                "OpenSSL failed to allocate TLS 1.3 PSK SSL object for {address} (hash: {})",
                self.hash_name
            )
        })?;

        if let Some(server_name) = server_name {
            ssl.set_hostname(server_name).with_context(|| {
                format!("OpenSSL failed to set TLS 1.3 PSK SNI for {address} (SNI configured)")
            })?;
        }

        let mut tls_stream = SslStream::new(ssl, stream).with_context(|| {
            format!("OpenSSL failed to attach the TLS 1.3 PSK SSL object to the TCP connection for {address}")
        })?;

        tokio_openssl::SslStream::connect(std::pin::Pin::new(&mut tls_stream))
            .await
            .with_context(|| {
                format!(
                    "OpenSSL TLS 1.3 PSK handshake failed for {address} (hash: {}, groups: {})",
                    self.hash_name,
                    format_groups(self.psk_dhe_ke_groups.as_ref())
                )
            })?;

        log::info!(
            target: module_path!(),
            "TLS 1.3 PSK connection established (address: {address}, hash: {}, groups: {})",
            self.hash_name,
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
    use tacacsrs_secrets::SecretBytes;

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
                cleartext_symmetric_key: Some(SecretBytes::new(key.to_vec())),
            }),
            central_keystore_reference: None,
        }
    }

    #[test]
    fn prepare_surfaces_context_errors_before_handshake() {
        let epsk = epsk_with_key(b"too-short");

        let Err(error) = PskClientConfig::prepare(&super::super::tls13_epsk::test_server(epsk))
        else {
            panic!("invalid PSK credentials must fail during preparation");
        };
        let message = format!("{error:#}");

        assert!(message.contains("Failed to prepare OpenSSL TLS 1.3 PSK context"));
        assert!(message.contains("PSK key must be at least 16 bytes"));
    }

    #[test]
    fn prepare_accepts_materialized_inline_secret() {
        let epsk = epsk_with_key(b"materialized-inline-secret");
        PskClientConfig::prepare(&super::super::tls13_epsk::test_server(epsk))
            .expect("materialized inline key must create an OpenSSL context");
    }

    #[tokio::test]
    async fn prepared_context_supports_repeated_psk_only_and_psk_dhe_connections() {
        use std::pin::Pin;
        use std::time::Duration;

        use openssl::ssl::{SslMethod, SslVersion};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tacacsrs_config::PskDheKeSupportedGroup;

        const KEY: &[u8] = b"prepared-key-for-loopback-handshakes";
        for groups in [vec![], vec![PskDheKeSupportedGroup::X25519]] {
            let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
            context
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            context
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            context.set_ciphersuites("TLS_AES_128_GCM_SHA256").unwrap();
            super::super::ffi::prefer_tls13_psk_only_key_exchange(&mut context);
            context.set_psk_server_callback(|_, identity, key| {
                if identity != Some(b"client-id".as_slice()) || key.len() < KEY.len() {
                    return Ok(0);
                }
                key[..KEY.len()].copy_from_slice(KEY);
                Ok(KEY.len())
            });
            let context = context.build();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let mut epsk = epsk_with_key(KEY);
            epsk.psk_dhe_ke_groups = groups;
            let config =
                PskClientConfig::prepare(&super::super::tls13_epsk::test_server(epsk)).unwrap();
            let peer = async {
                for _ in 0..2 {
                    let (tcp, _) = listener.accept().await?;
                    let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
                    Pin::new(&mut stream).accept().await?;
                    assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await?;
                    stream.write_all(&byte).await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let client = async {
                for marker in [17, 29] {
                    let tcp = TcpStream::connect(&address).await?;
                    let mut stream = config.connect(&address, None, tcp).await?;
                    stream.write_all(&[marker]).await?;
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await?;
                    assert_eq!(byte, [marker]);
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), async { tokio::try_join!(peer, client) })
                .await
                .expect("PSK loopback must complete")
                .unwrap();
        }
    }
}
