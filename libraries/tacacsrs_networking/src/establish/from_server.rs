//! Temporary YANG adapter for endpoint preparation.
//!
//! Stage 2 moves this adapter into the configuration preparation owner.
//! Client execution already consumes only prepared endpoint values.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_secrets::SecretBytes;

use crate::client::TacacsClient;
use crate::endpoint::PreparedEndpoint;
use crate::transport::{tls, tls_psk};

use super::{ConnectOptions, PreparedTransport};

/// Prepares transport material without opening a connection or changing `server`.
///
/// Credentials must already be materialized. TLS contexts are reusable across
/// connection attempts. DNS resolution and handshakes occur during execution.
///
/// # Errors
///
/// Returns an error if certificate, key, PSK, or native context preparation fails.
pub fn prepare_endpoint(
    server: &TacacsPlusServer,
    options: ConnectOptions,
) -> Result<PreparedEndpoint> {
    let references = tacacsrs_config::inspect_central_references(server)
        .context("Expand credential bundles before endpoint preparation")?;
    ensure!(references.is_empty(), "Resolve central credentials before endpoint preparation");
    if let Some(identity) = &server.client_identity {
        ensure!(
            identity.certificate.is_none() || identity.tls13_epsk.is_none(),
            "A TLS client identity cannot select both certificate and PSK authentication"
        );
    }
    let address = server.socket_address();
    let transport = if tls_psk::server_has_psk(server) {
        let (config, server_name) = tls_psk::prepare_from_server(server)?;
        PreparedTransport::Psk(config, server_name)
    } else if server.is_tls() {
        PreparedTransport::Tls(tls::prepare_from_server(
            server,
            &address,
            options.disable_certificate_verification,
        )?)
    } else {
        PreparedTransport::Tcp
    };

    Ok(PreparedEndpoint {
        address,
        single_connection: server.single_connection,
        obfuscation_key: server.obfuscation_key().map(SecretBytes::new),
        transport,
        options,
    })
}

impl TacacsClient {
    /// Prepares a YANG server and performs the configured preflight.
    ///
    /// # Errors
    ///
    /// Returns an error if preparation or the configured preflight fails.
    pub async fn connect(server: TacacsPlusServer, options: ConnectOptions) -> Result<Self> {
        Self::connect_prepared(prepare_endpoint(&server, options)?).await
    }

    /// Prepares a shared YANG server without retaining or changing it.
    ///
    /// # Errors
    ///
    /// Returns an error if preparation or the configured preflight fails.
    pub async fn connect_shared(
        server: Arc<TacacsPlusServer>,
        options: ConnectOptions,
    ) -> Result<Self> {
        Self::connect_prepared(prepare_endpoint(&server, options)?).await
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType};

    use super::*;

    fn builder() -> TacacsPlusServerBuilder {
        TacacsPlusServerBuilder::new("prepared", TacacsPlusServerType::all(), "127.0.0.1", 1)
    }

    #[test]
    fn preparation_preserves_the_source_and_redacts_runtime_state() {
        let server = builder()
            .with_shared_secret("private-obfuscation-key")
            .build();
        let original = server.clone();
        let endpoint = prepare_endpoint(&server, ConnectOptions::default()).unwrap();
        assert_eq!(server, original);
        assert_eq!(endpoint.address(), "127.0.0.1:1");
        assert_eq!(endpoint.single_connection(), server.single_connection);
        assert!(!format!("{endpoint:?}").contains("private-obfuscation-key"));
    }

    #[test]
    fn unresolved_credentials_fail_without_changing_references() {
        let mut server = builder()
            .with_tls13_epsk("client", b"valid-psk-credential".to_vec())
            .build();
        let identity = server.client_identity.as_mut().unwrap();
        identity.credentials_reference = Some("private-bundle-reference".to_owned());
        let original = server.clone();
        let error = prepare_endpoint(&server, ConnectOptions::default()).unwrap_err();
        assert!(error.to_string().contains("Expand credential bundles"));
        assert!(!format!("{error:#}").contains("private-bundle-reference"));
        assert_eq!(server, original);

        let identity = server.client_identity.as_mut().unwrap();
        identity.credentials_reference = None;
        let epsk = identity.tls13_epsk.as_mut().unwrap();
        epsk.inline_definition = None;
        epsk.central_keystore_reference = Some("private-central-reference".to_owned());
        let original = server.clone();
        let error = prepare_endpoint(&server, ConnectOptions::default()).unwrap_err();
        assert!(error.to_string().contains("Resolve central credentials"));
        assert!(!format!("{error:#}").contains("private-central-reference"));
        assert_eq!(server, original);
    }

    #[tokio::test]
    async fn lazy_client_rejects_invalid_or_incomplete_certificate_material() {
        for (certificate, key) in [
            (Some(b"invalid-der".to_vec()), Some(b"private-key-data".to_vec())),
            (None, Some(b"private-key-data".to_vec())),
            (Some(b"invalid-der".to_vec()), None),
            (None, None),
        ] {
            let server = builder()
                .with_tls_client_certificate(certificate, key)
                .build();
            let Err(error) = TacacsClient::connect(server, ConnectOptions::default()).await else {
                panic!("invalid certificate material must fail before the lazy client is returned");
            };
            assert!(!format!("{error:#}").contains("private-key-data"));
        }
    }

    #[tokio::test]
    async fn live_client_does_not_retain_the_source_model() {
        let server = Arc::new(
            builder()
                .with_tls13_epsk("client", b"valid-psk-credential".to_vec())
                .build(),
        );
        let weak = Arc::downgrade(&server);
        let client = TacacsClient::connect_shared(server, ConnectOptions::default())
            .await
            .unwrap();
        assert!(weak.upgrade().is_none());
        drop(client);
    }

    fn certificate() -> (openssl::x509::X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509, X509NameBuilder};

        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        (certificate.build(), key)
    }

    #[tokio::test]
    async fn prepared_tls_context_supports_repeated_tls_and_mtls_connections() {
        use std::pin::Pin;
        use std::time::Duration;

        use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_openssl::SslStream;
        use crate::transport::Transport;

        let (certificate, key) = certificate();
        for mutual_tls in [false, true] {
            let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
            context.set_certificate(&certificate).unwrap();
            context.set_private_key(&key).unwrap();
            context
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            context
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            if mutual_tls {
                context
                    .cert_store_mut()
                    .add_cert(certificate.clone())
                    .unwrap();
                context.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            }
            let context = context.build();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut server = if mutual_tls {
                builder()
                    .with_tls_client_certificate(
                        Some(certificate.to_der().unwrap()),
                        Some(key.private_key_to_der().unwrap()),
                    )
                    .build()
            } else {
                builder().with_tls_server_authentication().build()
            };
            server.port = address.port();
            let original = server.clone();
            let endpoint = prepare_endpoint(
                &server,
                ConnectOptions::default().with_certificate_verification_disabled(true),
            )
            .unwrap();
            assert_eq!(server, original);
            let peer = async {
                for _ in 0..2 {
                    let (tcp, _) = listener.accept().await?;
                    let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
                    Pin::new(&mut stream).accept().await?;
                    assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
                    assert_eq!(stream.ssl().peer_certificate().is_some(), mutual_tls);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await?;
                    stream.write_all(&byte).await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let client = async {
                for marker in [17, 29] {
                    let endpoint = endpoint.clone();
                    let stream = crate::establish::establish_stream(&endpoint).await?;
                    let (mut reader, mut writer) = stream.split();
                    writer.write_all(&[marker]).await?;
                    let mut byte = [0];
                    reader.read_exact(&mut byte).await?;
                    assert_eq!(byte, [marker]);
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), async { tokio::try_join!(peer, client) })
                .await
                .expect("TLS loopback must complete")
                .unwrap();
        }
    }
}
