use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspRequest, OcspResponse, OcspResponseStatus};
use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVersion};
use openssl::x509::X509;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_config::prepare::{prepare_endpoint, PrepareOptions};
use tacacsrs_networking::{RequestDeadline, TacacsClient};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "tacacsrs-ocsp-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../lde/containers/config/certificates")
}

async fn signed_response(
    directory: &Path,
    certificate: &X509,
    status: &str,
    next_minutes: Option<u32>,
) -> Result<Vec<u8>> {
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let mut request = OcspRequest::new()?;
    request.add_id(OcspCertId::from_cert(MessageDigest::sha1(), certificate, &issuer)?)?;
    std::fs::write(directory.join("request.der"), request.to_der()?)?;
    let serial = certificate.serial_number().to_bn()?.to_hex_str()?;
    let index = match status {
        "good" => format!("V\t351231235959Z\t\t{serial}\tunknown\t/CN=test\n"),
        "revoked" => format!("R\t351231235959Z\t200101000000Z\t{serial}\tunknown\t/CN=test\n"),
        _ => String::new(),
    };
    std::fs::write(directory.join("index.txt"), index)?;
    let mut command = tokio::process::Command::new("openssl");
    command
        .kill_on_drop(true)
        .arg("ocsp")
        .arg("-index")
        .arg(directory.join("index.txt"))
        .arg("-rsigner")
        .arg(fixtures().join("ca.crt"))
        .arg("-rkey")
        .arg(fixtures().join("ca.key"))
        .arg("-CA")
        .arg(fixtures().join("ca.crt"))
        .arg("-reqin")
        .arg(directory.join("request.der"))
        .arg("-respout")
        .arg(directory.join("response.der"))
        .arg("-resp_no_certs");
    if let Some(minutes) = next_minutes {
        command.arg("-nmin").arg(minutes.to_string());
    }
    let output = tokio::time::timeout(Duration::from_secs(10), command.output()).await??;
    anyhow::ensure!(
        output.status.success(),
        "OpenSSL fixture response generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(std::fs::read(directory.join("response.der"))?)
}

fn peer_context(staple: Option<Vec<u8>>, issuer: &X509) -> Result<SslContext> {
    let certificate = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("server.key"))?)?;
    let mut context = SslContext::builder(SslMethod::tls_server())?;
    context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_certificate(&certificate)?;
    context.set_private_key(&key)?;
    context.cert_store_mut().add_cert(issuer.clone())?;
    context.set_verify(
        openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    );
    if let Some(staple) = staple {
        context.set_status_callback(move |ssl| {
            ssl.set_ocsp_status(&staple)?;
            Ok(true)
        })?;
    }
    Ok(context.build())
}

async fn probe(staple: Option<Vec<u8>>, expiry: Option<Duration>) -> Result<bool> {
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let context = peer_context(staple, &issuer)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_certificate = X509::from_pem(&std::fs::read(fixtures().join("client.crt"))?)?;
    let client_key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("client.key"))?)?;
    let mut server = TacacsPlusServerBuilder::new(
        "ocsp",
        TacacsPlusServerType::all(),
        "127.0.0.1",
        listener.local_addr()?.port(),
    )
    .with_tls_client_certificate(
        Some(client_certificate.to_der()?),
        Some(client_key.private_key_to_pkcs8()?),
    )
    .build();
    server.server_authentication = Some(tacacsrs_config::TlsClientServerAuthentication::default());
    let authentication = server
        .server_authentication
        .as_mut()
        .context("test server authentication")?;
    authentication.ca_certs = Some(tacacsrs_config::ServerAuthenticationCaCerts {
        central_truststore_reference: None,
        inline_definition: Some(tacacsrs_config::truststore::CertsInlineDefinition {
            certificate: vec![tacacsrs_config::truststore::CertsCertificate {
                name: "issuer".to_owned(),
                cert_data: issuer.to_der()?,
            }],
        }),
    });
    authentication.require_stapled_ocsp = Some(tacacsrs_config::tacacsrs::RequireStapledOcsp {
        max_response_age_seconds: 300,
    });
    let original = server.clone();
    let endpoint = prepare_endpoint(&server, PrepareOptions::default())?;
    assert_eq!(server, original);
    let (closed, observed) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        if Pin::new(&mut stream).accept().await.is_ok() {
            assert!(
                stream.ssl().peer_certificate().is_some(),
                "good evidence must permit client authentication"
            );
            match stream.read(&mut [0]).await {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                result => anyhow::bail!("unexpected application data: {result:?}"),
            }
        } else {
            assert!(
                stream.ssl().peer_certificate().is_none(),
                "rejected evidence must not expose the client certificate"
            );
        }
        let _ = closed.send(());
        Ok::<(), anyhow::Error>(())
    });
    let client = TacacsClient::connect_prepared(endpoint).await?;
    let conversation = client.open_conversation().await;
    let accepted = conversation.is_ok();
    if let Some(expiry) = expiry.filter(|_| accepted) {
        tokio::time::pause();
        tokio::time::advance(expiry).await;
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(1), observed).await??;
    }
    if let Ok(mut conversation) = conversation {
        conversation.complete().await;
    }
    client
        .close_and_join(RequestDeadline::after(Duration::ZERO)?)
        .await?;
    tokio::time::timeout(Duration::from_secs(5), peer).await???;
    Ok(accepted)
}

#[tokio::test]
async fn required_staples_verify_signature_status_and_freshness_before_application_data(
) -> Result<()> {
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let other = X509::from_pem(&std::fs::read(fixtures().join("client.crt"))?)?;
    let good = signed_response(&directory.0, &server, "good", Some(1440)).await?;
    let revoked = signed_response(&directory.0, &server, "revoked", Some(1440)).await?;
    let unknown = signed_response(&directory.0, &server, "unknown", Some(1440)).await?;
    let wrong_peer = signed_response(&directory.0, &other, "good", Some(1440)).await?;
    let mut bad_signature = good.clone();
    *bad_signature.last_mut().context("test signature")? ^= 1;
    let mut trailing = good.clone();
    trailing.push(0);
    let unavailable = OcspResponse::create(OcspResponseStatus::TRY_LATER, None)?.to_der()?;
    for (label, staple, allowed) in [
        ("good", Some(good), true),
        ("missing", None, false),
        ("revoked", Some(revoked), false),
        ("unknown", Some(unknown), false),
        ("wrong peer", Some(wrong_peer), false),
        ("bad signature", Some(bad_signature), false),
        ("trailing data", Some(trailing), false),
        ("malformed", Some(vec![1, 2, 3]), false),
        ("unavailable", Some(unavailable), false),
    ] {
        assert_eq!(
            probe(staple, allowed.then_some(Duration::from_secs(301))).await?,
            allowed,
            "{label}"
        );
    }
    let short = signed_response(&directory.0, &server, "good", Some(1)).await?;
    assert!(probe(Some(short), Some(Duration::from_secs(61))).await?);
    let no_next = signed_response(&directory.0, &server, "good", None).await?;
    let response = OcspResponse::from_der(&no_next)?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let identifier = OcspCertId::from_cert(MessageDigest::sha1(), &server, &issuer)?;
    assert!(response
        .basic()?
        .find_status(&identifier)
        .context("test OCSP status")?
        .next_update()
        .is_none());
    assert!(probe(Some(no_next), Some(Duration::from_secs(301))).await?);
    Ok(())
}
