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

pub(super) struct Directory(pub(super) PathBuf);

impl Directory {
    pub(super) fn new() -> Result<Self> {
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

pub(super) fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../lde/containers/config/certificates")
}

pub(super) async fn signed_response(
    directory: &Path,
    certificate: &X509,
    status: &str,
    next_minutes: Option<u32>,
) -> Result<Vec<u8>> {
    signed_response_with_responder(directory, certificate, status, next_minutes, None, None).await
}

async fn signed_response_with_responder(
    directory: &Path,
    certificate: &X509,
    status: &str,
    next_minutes: Option<u32>,
    responder: Option<(&X509, &PKey<openssl::pkey::Private>)>,
    extra_certificate: Option<&X509>,
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
    let (signer, signing_key) = if let Some((certificate, key)) = responder {
        let signer = directory.join("responder.pem");
        let signing_key = directory.join("responder.key");
        std::fs::write(&signer, certificate.to_pem()?)?;
        std::fs::write(&signing_key, key.private_key_to_pem_pkcs8()?)?;
        (signer, signing_key)
    } else {
        (fixtures().join("ca.crt"), fixtures().join("ca.key"))
    };
    let mut command = tokio::process::Command::new("openssl");
    command
        .kill_on_drop(true)
        .arg("ocsp")
        .arg("-index")
        .arg(directory.join("index.txt"))
        .arg("-rsigner")
        .arg(signer)
        .arg("-rkey")
        .arg(signing_key)
        .arg("-CA")
        .arg(fixtures().join("ca.crt"))
        .arg("-reqin")
        .arg(directory.join("request.der"))
        .arg("-respout")
        .arg(directory.join("response.der"));
    if responder.is_none() {
        command.arg("-resp_no_certs");
    }
    if let Some(certificate) = extra_certificate {
        let path = directory.join("extra.pem");
        std::fs::write(&path, certificate.to_pem()?)?;
        command.arg("-rother").arg(path);
    }
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
    peer_context_with_version(staple, issuer, SslVersion::TLS1_3)
}

fn peer_context_with_version(
    staple: Option<Vec<u8>>,
    issuer: &X509,
    version: SslVersion,
) -> Result<SslContext> {
    let certificate = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("server.key"))?)?;
    let mut context = SslContext::builder(SslMethod::tls_server())?;
    context.set_min_proto_version(Some(version))?;
    context.set_max_proto_version(Some(version))?;
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

async fn protocol_mismatch_with_required_evidence(
    require_staple: bool,
    crls: Option<Vec<Vec<u8>>>,
) -> Result<()> {
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let context = peer_context_with_version(None, &issuer, SslVersion::TLS1_2)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_certificate = X509::from_pem(&std::fs::read(fixtures().join("client.crt"))?)?;
    let client_key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("client.key"))?)?;
    let mut server = TacacsPlusServerBuilder::new(
        "protocol-mismatch",
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
    authentication.require_stapled_ocsp =
        require_staple.then_some(tacacsrs_config::tacacsrs::RequireStapledOcsp {
            max_response_age_seconds: 300,
        });
    authentication.require_crls = crls.map(|lists| tacacsrs_config::tacacsrs::RequireCrls {
        max_age_seconds: 300,
        crl: Some(lists),
        evidence_reference: None,
    });
    let endpoint = prepare_endpoint(&server, PrepareOptions::default())?;
    let counters = endpoint.counters();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        anyhow::ensure!(
            Pin::new(&mut stream).accept().await.is_err(),
            "the TLS protocol mismatch must reject the peer"
        );
        Ok::<(), anyhow::Error>(())
    });

    let client = TacacsClient::connect_prepared(endpoint).await?;
    let conversation =
        tokio::time::timeout(Duration::from_secs(5), client.open_conversation()).await?;
    let Err(error) = conversation else {
        anyhow::bail!("the TLS protocol mismatch must reject the client");
    };
    assert!(
        error
            .chain()
            .any(|cause| cause.downcast_ref::<openssl::error::ErrorStack>().is_some()),
        "the native TLS error must remain in the chain: {error:#}"
    );
    let diagnostics = counters.snapshot().diagnostics;
    assert_eq!(diagnostics.handshake_attempts, 1);
    assert_eq!(diagnostics.handshake_failures, 1);
    assert_eq!(diagnostics.tls_protocol_mismatches, 1);
    assert_eq!(diagnostics.tls_other_errors, 0);
    assert_eq!(diagnostics.tls_certificate_errors, 0);
    assert_eq!(counters.snapshot().cert_errors, 0);
    client
        .close_and_join(RequestDeadline::after(Duration::ZERO)?)
        .await?;
    tokio::time::timeout(Duration::from_secs(5), peer).await???;
    Ok(())
}

#[tokio::test]
async fn native_protocol_failure_precedes_missing_required_evidence() -> Result<()> {
    let directory = Directory::new()?;
    let crl = super::crl_peer::make_crl(&directory.0, false, false).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        protocol_mismatch_with_required_evidence(true, None).await?;
        protocol_mismatch_with_required_evidence(false, Some(vec![crl.clone()])).await?;
        protocol_mismatch_with_required_evidence(true, Some(vec![crl])).await
    })
    .await?
}

#[derive(Debug, Clone, Copy)]
enum ResponderCase {
    Authorized,
    MissingUsage,
    WrongUsage,
    WrongKeyUsage,
    MissingKeyUsage,
    MissingNoCheck,
    MalformedNoCheck,
    CriticalNoCheck,
    DuplicateNoCheck,
    Expired,
    Future,
    WrongIssuer,
}

fn delegated_responder(case: ResponderCase) -> Result<(X509, PKey<openssl::pkey::Private>)> {
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::x509::{X509Extension, X509NameBuilder};
    use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let issuer_key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Test OCSP responder")?;
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_serial_number(
        openssl::bn::BigNum::from_u32(4000)?
            .to_asn1_integer()?
            .as_ref(),
    )?;
    certificate.set_subject_name(&name.build())?;
    certificate.set_issuer_name(issuer.subject_name())?;
    certificate.set_pubkey(&key)?;
    let (start, end) = match case {
        ResponderCase::Expired => (now - 120, now - 60),
        ResponderCase::Future => (now + 60, now + 120),
        _ => (now - 60, now + 60),
    };
    certificate.set_not_before(Asn1Time::from_unix(start.try_into()?)?.as_ref())?;
    certificate.set_not_after(Asn1Time::from_unix(end.try_into()?)?.as_ref())?;
    certificate.append_extension(BasicConstraints::new().build()?)?;
    let mut usage = KeyUsage::new();
    if matches!(case, ResponderCase::WrongKeyUsage) {
        usage.key_encipherment();
    } else {
        usage.digital_signature();
    }
    if !matches!(case, ResponderCase::MissingKeyUsage) {
        certificate.append_extension(usage.build()?)?;
    }
    if !matches!(case, ResponderCase::MissingUsage) {
        let mut usage = ExtendedKeyUsage::new();
        if matches!(case, ResponderCase::WrongUsage) {
            usage.server_auth();
        } else {
            usage.other("OCSPSigning");
        }
        certificate.append_extension(usage.build()?)?;
    }
    if !matches!(case, ResponderCase::MissingNoCheck) {
        let no_check = Asn1Object::from_str("1.3.6.1.5.5.7.48.1.5")?;
        let encoded = if matches!(case, ResponderCase::MalformedNoCheck) {
            &[0x01, 0x01, 0x00][..]
        } else {
            &[0x05, 0x00][..]
        };
        let value = Asn1OctetString::new_from_bytes(encoded)?;
        for _ in 0..if matches!(case, ResponderCase::DuplicateNoCheck) {
            2
        } else {
            1
        } {
            certificate.append_extension(X509Extension::new_from_der(
                &no_check,
                matches!(case, ResponderCase::CriticalNoCheck),
                &value,
            )?)?;
        }
    }
    let signing_key = if matches!(case, ResponderCase::WrongIssuer) {
        &key
    } else {
        &issuer_key
    };
    certificate.sign(signing_key, MessageDigest::sha256())?;
    Ok((certificate.build(), key))
}

#[tokio::test]
async fn delegated_staple_uses_authorized_responder_and_its_expiry() -> Result<()> {
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let (responder, key) = delegated_responder(ResponderCase::Authorized)?;
    let response = signed_response_with_responder(
        &directory.0,
        &server,
        "good",
        Some(1440),
        Some((&responder, &key)),
        None,
    )
    .await?;
    assert!(
        probe(Some(response), Some(Duration::from_secs(61))).await?,
        "authorized delegated responder must be accepted"
    );
    let (responder, key) = delegated_responder(ResponderCase::MissingKeyUsage)?;
    let (unused, _) = delegated_responder(ResponderCase::Expired)?;
    let response = signed_response_with_responder(
        &directory.0,
        &server,
        "good",
        Some(1440),
        Some((&responder, &key)),
        Some(&unused),
    )
    .await?;
    assert!(
        probe(Some(response), Some(Duration::from_secs(61))).await?,
        "unused expired certificates must not constrain the selected responder"
    );
    Ok(())
}

#[tokio::test]
async fn delegated_staples_reject_unauthorized_or_unusable_responders() -> Result<()> {
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    for case in [
        ResponderCase::MissingUsage,
        ResponderCase::WrongUsage,
        ResponderCase::WrongKeyUsage,
        ResponderCase::MissingNoCheck,
        ResponderCase::MalformedNoCheck,
        ResponderCase::CriticalNoCheck,
        ResponderCase::DuplicateNoCheck,
        ResponderCase::Expired,
        ResponderCase::Future,
        ResponderCase::WrongIssuer,
    ] {
        let (responder, key) = delegated_responder(case)?;
        let response = signed_response_with_responder(
            &directory.0,
            &server,
            "good",
            Some(1440),
            Some((&responder, &key)),
            None,
        )
        .await?;
        assert!(!probe(Some(response), None).await?, "rejected responder case: {case:?}");
    }
    Ok(())
}

async fn probe(staple: Option<Vec<u8>>, expiry: Option<Duration>) -> Result<bool> {
    probe_with_crls(staple, expiry, None, 300).await
}

async fn probe_with_crls(
    staple: Option<Vec<u8>>,
    expiry: Option<Duration>,
    crls: Option<Vec<Vec<u8>>>,
    crl_maximum_age: u32,
) -> Result<bool> {
    probe_with_evidence(staple, expiry, crls, crl_maximum_age, None, true).await
}

async fn probe_with_evidence(
    staple: Option<Vec<u8>>,
    expiry: Option<Duration>,
    crls: Option<Vec<Vec<u8>>>,
    crl_maximum_age: u32,
    supplied: Option<Vec<u8>>,
    require_staple: bool,
) -> Result<bool> {
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
    authentication.require_stapled_ocsp =
        require_staple.then_some(tacacsrs_config::tacacsrs::RequireStapledOcsp {
            max_response_age_seconds: 300,
        });
    authentication.require_ocsp = supplied.map(|response| tacacsrs_config::tacacsrs::RequireOcsp {
        max_response_age_seconds: 300,
        response: Some(response),
        evidence_reference: None,
    });
    authentication.require_crls = crls.map(|lists| tacacsrs_config::tacacsrs::RequireCrls {
        max_age_seconds: crl_maximum_age,
        crl: Some(lists),
        evidence_reference: None,
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
    let counters = endpoint.counters();
    let client = TacacsClient::connect_prepared(endpoint).await?;
    let conversation = client.open_conversation().await;
    let accepted = conversation.is_ok();
    if let Err(error) = &conversation {
        if format!("{error:#}").contains("revoked") {
            assert_eq!(counters.snapshot().diagnostics.tls_revoked_certificates, 1);
        }
    }
    assert_eq!(counters.snapshot().diagnostics.handshake_successes, u64::from(accepted));
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
async fn fetched_ocsp_is_peer_bound_and_does_not_replace_mandatory_staples() -> Result<()> {
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let other = X509::from_pem(&std::fs::read(fixtures().join("client.crt"))?)?;
    let good = signed_response(&directory.0, &server, "good", Some(1440)).await?;
    assert!(
        probe_with_evidence(
            None,
            Some(Duration::from_secs(301)),
            None,
            300,
            Some(good.clone()),
            false
        )
        .await?
    );
    assert!(!probe_with_evidence(None, None, None, 300, Some(good.clone()), true).await?);
    assert!(
        probe_with_evidence(Some(good.clone()), None, None, 300, Some(good.clone()), true).await?
    );
    let wrong = signed_response(&directory.0, &other, "good", Some(1440)).await?;
    assert!(!probe_with_evidence(None, None, None, 300, Some(wrong), false).await?);
    let mut forged = good;
    *forged.last_mut().unwrap() ^= 1;
    assert!(!probe_with_evidence(None, None, None, 300, Some(forged), false).await?);
    let revoked = signed_response(&directory.0, &server, "revoked", Some(1440)).await?;
    assert!(!probe_with_evidence(None, None, None, 300, Some(revoked), false).await?);
    Ok(())
}

#[tokio::test]
async fn delegated_responder_without_no_check_uses_required_crls() -> Result<()> {
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let (responder, key) = delegated_responder(ResponderCase::MissingNoCheck)?;
    let response = signed_response_with_responder(
        &directory.0,
        &server,
        "good",
        Some(1440),
        Some((&responder, &key)),
        None,
    )
    .await?;
    let crl = super::crl_peer::make_crl(&directory.0, false, false).await?;
    assert!(
        probe_with_crls(
            Some(response.clone()),
            Some(Duration::from_secs(61)),
            Some(vec![crl]),
            300
        )
        .await?,
        "a directly authorized responder can use a valid issuer CRL instead of No Check"
    );
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let issuer_key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let first = super::crl_peer::make_scoped_crl(
        &directory.0,
        &issuer,
        &issuer_key,
        None,
        false,
        Some("onlysomereasons=keyCompromise\n"),
    )
    .await?;
    let remaining = "onlysomereasons=CACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold,privilegeWithdrawn,AACompromise\n";
    let second = super::crl_peer::make_scoped_crl(
        &directory.0,
        &issuer,
        &issuer_key,
        None,
        false,
        Some(remaining),
    )
    .await?;
    assert!(
        probe_with_crls(
            Some(response.clone()),
            Some(Duration::from_secs(61)),
            Some(vec![first.clone(), second]),
            300
        )
        .await?,
        "reason partitions must cover the peer and its non-exempt responder"
    );
    let revoked = super::crl_peer::make_scoped_crl(
        &directory.0,
        &issuer,
        &issuer_key,
        Some(&responder),
        false,
        Some(remaining),
    )
    .await?;
    assert!(
        !probe_with_crls(Some(response), None, Some(vec![first, revoked]), 300).await?,
        "responder revocation in any partition must reject authentication"
    );
    Ok(())
}

#[tokio::test]
async fn delegated_responder_revocation_uses_delta_crls() -> Result<()> {
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let issuer_key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let (responder, key) = delegated_responder(ResponderCase::MissingNoCheck)?;
    let response = signed_response_with_responder(
        &directory.0,
        &server,
        "good",
        Some(1440),
        Some((&responder, &key)),
        None,
    )
    .await?;
    let base = super::crl_peer::make_numbered_crl(
        &directory.0,
        &issuer,
        &issuer_key,
        None,
        false,
        Some("freshestCRL=URI:http://pki.example.test/delta.crl\n"),
        1,
    )
    .await?;
    for revoked in [false, true] {
        let delta = super::crl_peer::make_numbered_crl(
            &directory.0,
            &issuer,
            &issuer_key,
            revoked.then_some(&responder),
            false,
            Some("2.5.29.27=critical,DER:02:01:01\n"),
            2,
        )
        .await?;
        assert_eq!(
            probe_with_crls(
                Some(response.clone()),
                (!revoked).then_some(Duration::from_secs(61)),
                Some(vec![base.clone(), delta]),
                300
            )
            .await?,
            !revoked
        );
    }
    Ok(())
}

#[tokio::test]
async fn delegated_responder_uses_disjoint_certificate_scopes() -> Result<()> {
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let (responder, key) = delegated_responder(ResponderCase::MissingNoCheck)?;
    let response = signed_response_with_responder(
        &directory.0,
        &server,
        "good",
        Some(1440),
        Some((&responder, &key)),
        None,
    )
    .await?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let issuer_key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let authorities = super::crl_peer::make_scoped_crl(
        &directory.0,
        &issuer,
        &issuer_key,
        None,
        false,
        Some("onlyCA=TRUE\n"),
    )
    .await?;
    let end_entities = super::crl_peer::make_scoped_crl(
        &directory.0,
        &issuer,
        &issuer_key,
        None,
        false,
        Some("onlyuser=TRUE\n"),
    )
    .await?;
    assert!(
        probe_with_crls(
            Some(response.clone()),
            Some(Duration::from_secs(61)),
            Some(vec![authorities.clone(), end_entities]),
            300
        )
        .await?,
        "separate certificate types must cover the peer, issuer, and non-exempt responder"
    );
    let revoked = super::crl_peer::make_scoped_crl(
        &directory.0,
        &issuer,
        &issuer_key,
        Some(&responder),
        false,
        Some("onlyuser=TRUE\n"),
    )
    .await?;
    assert!(
        !probe_with_crls(Some(response), None, Some(vec![authorities, revoked]), 300).await?,
        "authority coverage must not hide responder revocation in end-entity scope"
    );
    Ok(())
}

#[tokio::test]
async fn combined_evidence_rejects_revoked_responders_and_conflicting_peer_status() -> Result<()> {
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let issuer_key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let (responder, key) = delegated_responder(ResponderCase::MissingNoCheck)?;
    let good = signed_response_with_responder(
        &directory.0,
        &server,
        "good",
        Some(1440),
        Some((&responder, &key)),
        None,
    )
    .await?;
    let good_crl = super::crl_peer::make_crl(&directory.0, false, false).await?;
    let stale_crl = super::crl_peer::make_crl(&directory.0, false, true).await?;
    let error = probe_with_crls(Some(good.clone()), None, Some(vec![stale_crl]), 300)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("CRL is stale"));
    let revoked_responder = super::crl_peer::make_issuer_crl(
        &directory.0,
        &issuer,
        &issuer_key,
        Some(&responder),
        false,
    )
    .await?;
    let revoked_peer = super::crl_peer::make_crl(&directory.0, true, false).await?;
    let mut forged = good_crl.clone();
    *forged.last_mut().unwrap() ^= 1;
    for (label, crl) in [
        ("responder revoked", revoked_responder),
        ("peer revoked", revoked_peer),
        ("forged CRL", forged),
    ] {
        assert!(!probe_with_crls(Some(good.clone()), None, Some(vec![crl]), 300).await?, "{label}");
    }
    for status in ["revoked", "unknown"] {
        let response = signed_response_with_responder(
            &directory.0,
            &server,
            status,
            Some(1440),
            Some((&responder, &key)),
            None,
        )
        .await?;
        assert!(
            !probe_with_crls(Some(response), None, Some(vec![good_crl.clone()]), 300).await?,
            "{status}"
        );
    }
    assert!(!probe_with_crls(None, None, Some(vec![good_crl.clone()]), 300).await?);
    assert!(
        probe_with_crls(Some(good), Some(Duration::from_secs(11)), Some(vec![good_crl]), 10)
            .await?,
        "CRL freshness must bound use before responder and OCSP expiry"
    );
    Ok(())
}

#[tokio::test]
async fn combined_evidence_preserves_responder_authorization_and_no_check_validation() -> Result<()>
{
    let directory = Directory::new()?;
    let server = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let crl = super::crl_peer::make_crl(&directory.0, false, false).await?;
    for case in [
        ResponderCase::WrongKeyUsage,
        ResponderCase::MissingUsage,
        ResponderCase::MalformedNoCheck,
        ResponderCase::CriticalNoCheck,
        ResponderCase::DuplicateNoCheck,
    ] {
        let (responder, key) = delegated_responder(case)?;
        let response = signed_response_with_responder(
            &directory.0,
            &server,
            "good",
            Some(1440),
            Some((&responder, &key)),
            None,
        )
        .await?;
        assert!(
            !probe_with_crls(Some(response), None, Some(vec![crl.clone()]), 300).await?,
            "{case:?}"
        );
    }
    let (responder, key) = delegated_responder(ResponderCase::Authorized)?;
    let response = signed_response_with_responder(
        &directory.0,
        &server,
        "good",
        Some(1440),
        Some((&responder, &key)),
        None,
    )
    .await?;
    assert!(probe_with_crls(Some(response), None, Some(vec![crl.clone()]), 300).await?);
    let response = signed_response(&directory.0, &server, "good", Some(1)).await?;
    assert!(
        probe_with_crls(Some(response), Some(Duration::from_secs(61)), Some(vec![crl]), 300)
            .await?,
        "OCSP freshness must still bound use before CRL expiry"
    );
    Ok(())
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
