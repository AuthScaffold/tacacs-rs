//! Prepared TLS 1.3 PSK client configuration.
//!
//! The PSK transport prepares and validates its OpenSSL context before the
//! async handshake. This separates configuration errors from handshake errors.

use anyhow::{Context, Result};
use openssl::ssl::Ssl;
use openssl::ssl::SslContext;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::context::{create_psk_ssl_context, PskHash, PskDheGroup};
use super::PskDheKeGroups;

/// Reusable TLS 1.3 PSK configuration with private native context ownership.
#[derive(Clone)]
pub struct PskClientConfig {
    hash_name: &'static str,
    psk_dhe_ke_groups: Option<PskDheKeGroups>,
    ssl_context: SslContext,
    server_name: Option<String>,
}

impl std::fmt::Debug for PskClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PskClientConfig")
            .field("hash", &self.hash_name)
            .field("groups", &format_groups(self.psk_dhe_ke_groups.as_ref()))
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl PskClientConfig {
    /// Prepares an OpenSSL TLS 1.3 PSK client context from EPSK configuration.
    ///
    /// Empty groups select PSK-only mode. Nonempty groups require PSK-DHE.
    /// Connections reject certificate fallback before TACACS+ I/O.
    /// Optional SNI must be a DNS name. Preparation validates it without DNS I/O.
    ///
    /// # Errors
    /// Returns an error for invalid identity, key, groups, or native configuration.
    pub fn prepare(
        identity: &str,
        key: &[u8],
        handshake_hash: PskHash,
        groups: &[PskDheGroup],
        server_name: Option<&str>,
    ) -> Result<Self> {
        if let Some(name) = server_name {
            anyhow::ensure!(
                name.parse::<std::net::IpAddr>().is_err(),
                "TLS SNI must be a DNS name, not an IP address"
            );
            crate::ServerAddress::new(name, 1).context("invalid TLS PSK SNI name")?;
        }
        let psk_dhe_ke_groups = PskDheKeGroups::new(groups);
        let ssl_context =
            create_psk_ssl_context(identity, key, handshake_hash, psk_dhe_ke_groups.as_ref())
                .with_context(|| {
                    format!(
                        "Failed to prepare OpenSSL TLS 1.3 PSK context (hash: {}, groups: {})",
                        handshake_hash.name(),
                        format_groups(psk_dhe_ke_groups.as_ref())
                    )
                })?;

        Ok(Self {
            hash_name: handshake_hash.name(),
            psk_dhe_ke_groups,
            ssl_context,
            server_name: server_name.map(str::to_owned),
        })
    }

    /// Establishes a TLS 1.3 PSK connection over the provided TCP connection.
    ///
    /// OpenSSL reports external-PSK authentication as session reuse. The client
    /// verifies that result and the negotiated key exchange before packet I/O.
    ///
    /// # Errors
    ///
    /// Returns an error if the OpenSSL `SslContext` or `Ssl` object cannot be
    /// created, if the TLS handshake fails, or if the negotiated authentication
    /// or key-exchange mode does not match the prepared PSK inputs.
    pub(crate) async fn connect(
        &self,
        address: &impl std::fmt::Display,
        stream: TcpStream,
    ) -> Result<SslStream<TcpStream>> {
        let mut ssl = Ssl::new(&self.ssl_context).with_context(|| {
            format!(
                "OpenSSL failed to allocate TLS 1.3 PSK SSL object for {address} (hash: {})",
                self.hash_name
            )
        })?;

        if let Some(server_name) = &self.server_name {
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

        anyhow::ensure!(
            tls_stream.ssl().session_reused(),
            "TLS 1.3 peer did not authenticate with the configured PSK"
        );
        let negotiated_dhe = super::ffi::negotiated_key_exchange_uses_dhe(tls_stream.ssl())?;
        anyhow::ensure!(
            negotiated_dhe == self.psk_dhe_ke_groups.is_some(),
            "TLS 1.3 PSK key-exchange mode mismatch: expected {}, negotiated {}",
            if self.psk_dhe_ke_groups.is_some() {
                "PSK-DHE"
            } else {
                "PSK-only"
            },
            if negotiated_dhe {
                "PSK-DHE"
            } else {
                "PSK-only"
            },
        );

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

    #[test]
    fn prepare_surfaces_context_errors_before_handshake() {
        let Err(error) =
            PskClientConfig::prepare("client-id", b"too-short", PskHash::Sha256, &[], None)
        else {
            panic!("invalid PSK credentials must fail during preparation");
        };
        let message = format!("{error:#}");

        assert!(message.contains("Failed to prepare OpenSSL TLS 1.3 PSK context"));
        assert!(message.contains("PSK key must be at least 16 bytes"));
    }

    #[test]
    fn prepare_accepts_materialized_inline_secret() {
        PskClientConfig::prepare(
            "client-id",
            b"materialized-inline-secret",
            PskHash::Sha256,
            &[],
            None,
        )
        .expect("materialized inline key must create an OpenSSL context");
    }

    #[test]
    fn debug_omits_identity_and_key() {
        let config = PskClientConfig::prepare(
            "private-client-id",
            b"materialized-inline-secret",
            PskHash::Sha256,
            &[],
            Some("psk.example"),
        )
        .unwrap();
        for rendered in [
            format!("{config:?}"),
            format!("{config:#?}"),
            format!("{:?}", crate::PreparedTransport::Psk(config)),
        ] {
            assert!(rendered.contains("psk.example"));
            assert!(!rendered.contains("materialized-inline-secret"));
            assert!(!rendered.contains("private-client-id"));
            assert!(!rendered.contains(&format!("{:?}", b"materialized-inline-secret")));
            assert!(!rendered.contains("ssl_context"));
        }
    }

    #[test]
    fn invalid_sni_is_rejected_during_preparation() {
        for name in [
            "bad\0name",
            "",
            "127.0.0.1",
            "::1",
            "*.example",
            "bad host",
            "127.1",
            "0x7f000001",
            "127.0.0.1.",
        ] {
            assert!(PskClientConfig::prepare(
                "client-id",
                b"materialized-inline-secret",
                PskHash::Sha256,
                &[],
                Some(name),
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn prepared_context_supports_repeated_psk_only_and_psk_dhe_connections() {
        use std::pin::Pin;
        use std::time::Duration;

        use openssl::ssl::{SslMethod, SslVersion};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        const KEY: &[u8] = b"prepared-key-for-loopback-handshakes";
        for groups in [vec![], vec![PskDheGroup::X25519]] {
            let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
            context
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            context
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            context.set_ciphersuites("TLS_AES_128_GCM_SHA256").unwrap();
            if groups.is_empty() {
                context.set_options(super::super::context::ALLOW_NO_DHE_KEX);
                context.set_groups_list("P-224").unwrap();
            }
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
            let config = PskClientConfig::prepare(
                "client-id",
                KEY,
                PskHash::Sha256,
                &groups,
                Some("psk_server.example."),
            )
            .unwrap();
            let peer = async {
                for _ in 0..2 {
                    let (tcp, _) = listener.accept().await?;
                    let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
                    Pin::new(&mut stream).accept().await?;
                    assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
                    assert_eq!(
                        stream.ssl().servername(openssl::ssl::NameType::HOST_NAME),
                        Some("psk_server.example.")
                    );
                    assert_eq!(stream.ssl().peer_tmp_key().is_ok(), !groups.is_empty());
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await?;
                    stream.write_all(&byte).await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let client = async {
                for marker in [17, 29] {
                    let tcp = TcpStream::connect(&address).await?;
                    let mut stream = config.connect(&address, tcp).await?;
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
