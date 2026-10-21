use std::pin::Pin;
use std::time::Duration;

use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

use super::*;
use crate::{
    BindingPolicy, CertificateIdentity, CertificateTrust, CertificateVerification, LocalBinding,
    PrivateKeyEncoding, PskClientConfig, PskDheGroup, PskHash, SourceBinding, TlsClientConfig,
};
use crate::transport::abstractions::Transport;

const PSK: &[u8] = b"test-only-binding-psk-material";
// OpenSSL's SSL_OP_ALLOW_NO_DHE_KEX permits TLS 1.3 PSK without DHE.
const ALLOW_NO_DHE_KEX: openssl::ssl::SslOptions =
    openssl::ssl::SslOptions::from_bits_retain(1 << 10);

fn certificate(name: &str) -> X509 {
    X509::from_pem(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../lde/containers/config/certificates")
                .join(format!("{name}.crt")),
        )
        .unwrap(),
    )
    .unwrap()
}

fn key(name: &str) -> PKey<openssl::pkey::Private> {
    PKey::private_key_from_pem(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../lde/containers/config/certificates")
                .join(format!("{name}.key")),
        )
        .unwrap(),
    )
    .unwrap()
}

fn transports(mode: u8) -> (PreparedTransport, Option<SslContext>) {
    if mode == 0 {
        return (PreparedTransport::Tcp, None);
    }
    let mut server = SslContext::builder(SslMethod::tls_server()).unwrap();
    server
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.set_num_tickets(0).unwrap();
    let transport = if mode <= 2 {
        server.set_certificate(&certificate("server")).unwrap();
        server.set_private_key(&key("server")).unwrap();
        let authority = certificate("ca").to_der().unwrap();
        let client_certificate = certificate("client").to_der().unwrap();
        let client_key = key("client").private_key_to_pkcs8().unwrap();
        if mode == 2 {
            server.cert_store_mut().add_cert(certificate("ca")).unwrap();
            server.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
        PreparedTransport::Tls(
            TlsClientConfig::prepare(
                "localhost",
                None,
                CertificateTrust::Certificates {
                    authorities: &[&authority],
                    end_entities: &[],
                },
                (mode == 2).then_some(CertificateIdentity {
                    certificate: &client_certificate,
                    intermediates: &[],
                    public_key_info: None,
                    private_key: &client_key,
                    private_key_encoding: PrivateKeyEncoding::Pkcs8,
                }),
                CertificateVerification::Required,
            )
            .unwrap(),
        )
    } else {
        server.set_ciphersuites("TLS_AES_128_GCM_SHA256").unwrap();
        if mode == 3 {
            server.set_options(ALLOW_NO_DHE_KEX);
            server.set_groups_list("P-224").unwrap();
        }
        server.set_psk_server_callback(|_, identity, output| {
            assert_eq!(identity, Some(b"binding-client".as_slice()));
            output[..PSK.len()].copy_from_slice(PSK);
            Ok(PSK.len())
        });
        let groups = if mode == 3 {
            vec![]
        } else {
            vec![PskDheGroup::X25519]
        };
        PreparedTransport::Psk(
            PskClientConfig::prepare("binding-client", PSK, PskHash::Sha256, &groups, None)
                .unwrap(),
        )
    };
    (transport, Some(server.build()))
}

#[tokio::test]
async fn every_transport_uses_strict_source_and_device_binding_and_scoped_fallback() {
    for mode in 0..5 {
        let (transport, server) = transports(mode);
        for (device, policy) in [
            ("lo", BindingPolicy::Strict),
            ("trs-missing", BindingPolicy::BestEffort),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let binding = LocalBinding::new(
                Some(SourceBinding::Ip("127.0.0.2".parse().unwrap())),
                Some(device),
                None,
                policy,
            )
            .unwrap();
            let endpoint = PreparedEndpoint::new(
                listener.local_addr().unwrap().try_into().unwrap(),
                transport.clone(),
                false,
                None,
                ConnectOptions::default()
                    .with_timeout(Duration::from_secs(2))
                    .with_local_binding(binding),
            );
            let peer = async {
                let (mut tcp, remote) = listener.accept().await.unwrap();
                assert_eq!(remote.ip().to_string(), "127.0.0.2", "mode {mode}");
                if let Some(context) = &server {
                    let mut tls = SslStream::new(Ssl::new(context).unwrap(), tcp).unwrap();
                    Pin::new(&mut tls).accept().await.unwrap();
                    if mode == 2 {
                        assert!(tls.ssl().peer_certificate().is_some());
                    }
                    tls.write_all(&[42]).await.unwrap();
                    let mut response = [0];
                    tls.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, [24]);
                } else {
                    tcp.write_all(&[42]).await.unwrap();
                    let mut response = [0];
                    tcp.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, [24]);
                }
            };
            let client = async {
                let transport = establish_stream(&endpoint).await.unwrap();
                let (mut reader, mut writer) = transport.split();
                let mut message = [0];
                reader.read_exact(&mut message).await.unwrap();
                assert_eq!(message, [42]);
                writer.write_all(&[24]).await.unwrap();
            };
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(peer, client) })
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn strict_device_failure_precedes_every_handshake() {
    for mode in 0..5 {
        let (transport, _) = transports(mode);
        let endpoint = PreparedEndpoint::new(
            crate::ServerAddress::new("127.0.0.1", 49).unwrap(),
            transport,
            false,
            None,
            ConnectOptions::default().with_local_binding(
                LocalBinding::new(None, Some("trs-missing"), None, BindingPolicy::Strict).unwrap(),
            ),
        );
        assert!(establish_stream(&endpoint).await.is_err());
        assert_eq!(
            endpoint
                .counters()
                .snapshot()
                .diagnostics
                .handshake_attempts,
            0
        );
    }
}
