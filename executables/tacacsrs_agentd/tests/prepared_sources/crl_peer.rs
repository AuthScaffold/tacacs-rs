use std::fmt::Write as _;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVersion, SslVerifyMode};
use openssl::x509::{X509, X509Crl};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

use tacacsrs_config::{TacacsPlus, TacacsPlusServerBuilder, TacacsPlusServerType, ValidationOptions};
use tacacsrs_config::prepare::{enumerate_materialized_servers, prepare_endpoint, PrepareOptions};
use tacacsrs_credential_http::{CrlFetchLimits, HttpCrlResolver, HttpCrlSource};
use tacacsrs_credential_resolution::{
    CertificateRevocationListsMaterial, CredentialResolver, CredentialValidity,
    FakeCredentialResolver, PublicBytes, RequestSlot, ResolvedCredential,
};
use tacacsrs_networking::{RequestDeadline, TacacsClient};

use super::ocsp_peer::{Directory, fixtures};

struct RefreshingCrlResolver {
    crl: Vec<u8>,
    validity: std::sync::Mutex<CredentialValidity>,
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl tacacsrs_credential_resolution::CredentialResolver for RefreshingCrlResolver {
    async fn resolve(
        &self,
        request: &tacacsrs_credential_resolution::CredentialRequest,
    ) -> Result<ResolvedCredential, tacacsrs_credential_resolution::ResolutionError> {
        use tacacsrs_credential_resolution::{CredentialKind, ProviderErrorKind, ResolutionError};
        if request.kind() != CredentialKind::CertificateRevocationLists {
            return Err(ResolutionError::provider(
                ProviderErrorKind::Unavailable,
                request.context(),
            ));
        }
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(ResolvedCredential::CertificateRevocationLists(CertificateRevocationListsMaterial {
            validity: *self.validity.lock().unwrap(),
            lists: vec![PublicBytes::new(self.crl.clone())],
        }))
    }
}

#[tokio::test]
async fn provider_crl_validity_refreshes_before_expiry_without_notifications() -> Result<()> {
    use std::sync::Arc;
    use std::time::SystemTime;
    use tacacsrs_agent::{EnabledServices, RuntimeHealthPublisher, ServiceConfig, TacacsClientService};
    use tacacsrs_agent::runtime::{ConfigSupervisor, NoopTacacsPlusFilter};
    use tacacsrs_config::source::{ConfigDatastore, StaticDatastore};
    let directory = Directory::new()?;
    let crl = make_crl(&directory.0, false, false).await?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let source = source_for(&issuer, 449, std::slice::from_ref(&crl), true, true)?;
    let original = source.clone();
    let source = Arc::new(StaticDatastore::new(source));
    let resolver = Arc::new(RefreshingCrlResolver {
        crl,
        validity: std::sync::Mutex::new(CredentialValidity::new(
            None,
            Some(SystemTime::now() + Duration::from_secs(20)),
        )?),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = Arc::new(TacacsClientService::waiting_for_configuration(
        ServiceConfig {
            local_services: tacacsrs_config::tacacsrs::LocalServices::default(),
            tacacs_plus: TacacsPlus::empty(),
            validation_options: ValidationOptions::default(),
            runtime_policy: tacacsrs_agent::RuntimePolicy::default(),
            disable_certificate_verification: false,
        },
        health.clone(),
    )?);
    let mut supervisor = ConfigSupervisor::new(
        source.clone(),
        service.clone(),
        health.clone(),
        Arc::new(NoopTacacsPlusFilter::default()),
    )
    .with_credential_resolver(resolver.clone());
    supervisor.initialize_until(std::future::pending()).await?;
    let previous = health.snapshot();
    *resolver.validity.lock().unwrap() = CredentialValidity::unbounded();
    let stop = tokio_util::sync::CancellationToken::new();
    tokio::time::pause();
    let running = supervisor.run_until(stop.cancelled());
    tokio::pin!(running);
    assert!(futures_util::poll!(&mut running).is_pending());
    tokio::time::advance(Duration::from_secs(11)).await;
    assert!(futures_util::poll!(&mut running).is_pending());
    let refreshed = health.snapshot();
    assert_eq!(resolver.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(service.server_count(), 1);
    assert_eq!(
        refreshed.materialization_revision().unwrap().source(),
        previous.materialization_revision().unwrap().source()
    );
    assert!(
        refreshed
            .materialization_revision()
            .unwrap()
            .credentials()
            .value()
            > previous
                .materialization_revision()
                .unwrap()
                .credentials()
                .value()
    );
    assert!(
        refreshed.credential_validity().unwrap().valid_until()
            > previous.credential_validity().unwrap().valid_until()
    );
    assert_eq!(source.load().await?, original);
    stop.cancel();
    running.await?;
    Ok(())
}

pub(super) async fn make_crl(directory: &Path, revoked: bool, stale: bool) -> Result<Vec<u8>> {
    let peer = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    make_issuer_crl(directory, &issuer, &key, revoked.then_some(&peer), stale).await
}

pub(super) async fn make_issuer_crl(
    directory: &Path,
    issuer: &X509,
    key: &PKey<openssl::pkey::Private>,
    revoked: Option<&X509>,
    stale: bool,
) -> Result<Vec<u8>> {
    make_scoped_crl(directory, issuer, key, revoked, stale, None).await
}

pub(super) async fn make_scoped_crl(
    directory: &Path,
    issuer: &X509,
    key: &PKey<openssl::pkey::Private>,
    revoked: Option<&X509>,
    stale: bool,
    scope: Option<&str>,
) -> Result<Vec<u8>> {
    let extensions =
        scope.map(|scope| format!("issuingDistributionPoint=critical,@scope\n[scope]\n{scope}"));
    make_extended_crl(directory, issuer, key, revoked, stale, extensions.as_deref()).await
}

async fn make_extended_crl(
    directory: &Path,
    issuer: &X509,
    key: &PKey<openssl::pkey::Private>,
    revoked: Option<&X509>,
    stale: bool,
    extensions: Option<&str>,
) -> Result<Vec<u8>> {
    make_numbered_crl(directory, issuer, key, revoked, stale, extensions, 1).await
}

pub(super) async fn make_numbered_crl(
    directory: &Path,
    issuer: &X509,
    key: &PKey<openssl::pkey::Private>,
    revoked: Option<&X509>,
    stale: bool,
    extensions: Option<&str>,
    number: impl Into<Option<u32>>,
) -> Result<Vec<u8>> {
    let number = number.into();
    let index = match revoked {
        Some(peer) => format!(
            "R\t351231235959Z\t200101000000Z\t{}\tunknown\t/CN=test\n",
            peer.serial_number().to_bn()?.to_hex_str()?
        ),
        None => String::new(),
    };
    std::fs::write(directory.join("index.txt"), index)?;
    if let Some(number) = number {
        std::fs::write(directory.join("number"), format!("{number:02X}\n"))?;
    }
    std::fs::write(directory.join("issuer.pem"), issuer.to_pem()?)?;
    std::fs::write(directory.join("issuer.key"), key.private_key_to_pem_pkcs8()?)?;
    let mut configuration = format!("[ca]\ndefault_ca=issuer\n[issuer]\ndatabase={}\ncertificate={}\nprivate_key={}\ndefault_md=sha256\ndefault_crl_days=1\n", directory.join("index.txt").display(), directory.join("issuer.pem").display(), directory.join("issuer.key").display());
    if number.is_some() {
        writeln!(configuration, "crlnumber={}", directory.join("number").display())?;
    }
    if let Some(extensions) = extensions {
        configuration.push_str("crl_extensions=crl_extensions\n[crl_extensions]\n");
        configuration.push_str(extensions);
    }
    std::fs::write(directory.join("ca.cnf"), configuration)?;
    generate_crl(directory, stale).await
}

async fn generate_crl(directory: &Path, stale: bool) -> Result<Vec<u8>> {
    let mut command = tokio::process::Command::new("openssl");
    command
        .kill_on_drop(true)
        .args(["ca", "-gencrl", "-batch", "-config"])
        .arg(directory.join("ca.cnf"))
        .arg("-out")
        .arg(directory.join("crl.pem"));
    if stale {
        command.args([
            "-crl_lastupdate",
            "20200101000000Z",
            "-crl_nextupdate",
            "20200102000000Z",
        ]);
    }
    let output = tokio::time::timeout(Duration::from_secs(10), command.output()).await??;
    anyhow::ensure!(
        output.status.success(),
        "CRL fixture generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(X509Crl::from_pem(&std::fs::read(directory.join("crl.pem"))?)?.to_der()?)
}

struct PeerIdentity {
    certificate: X509,
    key: PKey<openssl::pkey::Private>,
    chain: Vec<X509>,
}

fn peer_context(issuer: &X509, identity: Option<&PeerIdentity>) -> Result<SslContext> {
    let mut context = SslContext::builder(SslMethod::tls_server())?;
    context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    if let Some(identity) = identity {
        context.set_certificate(&identity.certificate)?;
        context.set_private_key(&identity.key)?;
        for certificate in &identity.chain {
            context.add_extra_chain_cert(certificate.clone())?;
        }
    } else {
        context.set_certificate(
            X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?.as_ref(),
        )?;
        context.set_private_key(
            PKey::private_key_from_pem(&std::fs::read(fixtures().join("server.key"))?)?.as_ref(),
        )?;
    }
    context.cert_store_mut().add_cert(issuer.clone())?;
    context.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    Ok(context.build())
}

pub(super) fn source_for(
    issuer: &X509,
    port: u16,
    lists: &[Vec<u8>],
    provider: bool,
    bundle: bool,
) -> Result<TacacsPlus> {
    let mut server =
        TacacsPlusServerBuilder::new("crls", TacacsPlusServerType::all(), "127.0.0.1", port)
            .with_tls_client_certificate(
                Some(X509::from_pem(&std::fs::read(fixtures().join("client.crt"))?)?.to_der()?),
                Some(
                    PKey::private_key_from_pem(&std::fs::read(fixtures().join("client.key"))?)?
                        .private_key_to_pkcs8()?,
                ),
            )
            .build();
    server.server_authentication = Some(tacacsrs_config::TlsClientServerAuthentication {
        ca_certs: Some(tacacsrs_config::ServerAuthenticationCaCerts {
            central_truststore_reference: None,
            inline_definition: Some(tacacsrs_config::truststore::CertsInlineDefinition {
                certificate: vec![tacacsrs_config::truststore::CertsCertificate {
                    name: "root".to_owned(),
                    cert_data: issuer.to_der()?,
                }],
            }),
        }),
        require_crls: Some(tacacsrs_config::tacacsrs::RequireCrls {
            max_age_seconds: 300,
            crl: (!provider).then(|| lists.to_vec()),
            evidence_reference: provider.then(|| "opaque-crls".to_owned()),
        }),
        ..Default::default()
    });
    let mut source = TacacsPlus {
        server: vec![server],
        ..TacacsPlus::empty()
    };
    if bundle {
        let authentication = source.server[0].server_authentication.as_mut().unwrap();
        source
            .server_credentials
            .push(tacacsrs_config::ServerCredentials {
                id: "trust".to_owned(),
                ca_certs: authentication.ca_certs.take(),
                require_crls: authentication.require_crls.take(),
                require_ocsp: None,
                ee_certs: None,
                tls13_epsks: None,
                require_stapled_ocsp: None,
            });
        authentication.credentials_reference = Some("trust".to_owned());
    }
    Ok(source)
}

async fn probe(
    lists: &[Vec<u8>],
    provider: bool,
    bundle: bool,
    expect_expiry: bool,
    identity: Option<&PeerIdentity>,
) -> Result<bool> {
    let resolver = if provider {
        FakeCredentialResolver::new().with_response(
            RequestSlot::from_index(0),
            ResolvedCredential::CertificateRevocationLists(CertificateRevocationListsMaterial {
                validity: CredentialValidity::unbounded(),
                lists: lists.iter().cloned().map(PublicBytes::new).collect(),
            }),
        )
    } else {
        FakeCredentialResolver::new()
    };
    probe_with_resolver(lists, provider, bundle, expect_expiry, identity, &resolver).await
}

async fn probe_with_resolver(
    lists: &[Vec<u8>],
    provider: bool,
    bundle: bool,
    expect_expiry: bool,
    identity: Option<&PeerIdentity>,
    resolver: &dyn CredentialResolver,
) -> Result<bool> {
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let context = peer_context(&issuer, identity)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let source = source_for(&issuer, listener.local_addr()?.port(), lists, provider, bundle)?;
    let original = source.clone();
    let materialized =
        enumerate_materialized_servers(&source, resolver, &ValidationOptions::default()).await?;
    let endpoint = prepare_endpoint(materialized[0].server(), PrepareOptions::default());
    assert_eq!(source, original);
    let Ok(endpoint) = endpoint else {
        return Ok(false);
    };
    assert!(endpoint.revocation_evidence_validity().is_some());
    let (handshake_complete, handshake_observed) = tokio::sync::oneshot::channel();
    let (closed, observed) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        if Pin::new(&mut stream).accept().await.is_ok() {
            let _ = handshake_complete.send(());
            assert!(stream.ssl().peer_certificate().is_some());
            match stream.read(&mut [0]).await {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                result => anyhow::bail!("unexpected application bytes: {result:?}"),
            }
        } else {
            assert!(
                stream.ssl().peer_certificate().is_none(),
                "revoked paths must fail before client authentication"
            );
        }
        let _ = closed.send(());
        Ok::<(), anyhow::Error>(())
    });
    let counters = endpoint.counters();
    let client = TacacsClient::connect_prepared(endpoint).await?;
    let session = client.open_conversation().await;
    if let Err(error) = &session {
        eprintln!("Native CRL handshake rejected: {error:#}");
        if format!("{error:#}").contains("revoked") {
            assert_eq!(counters.snapshot().diagnostics.tls_revoked_certificates, 1);
        }
    }
    let accepted = session.is_ok();
    assert_eq!(counters.snapshot().diagnostics.handshake_successes, u64::from(accepted));
    if accepted {
        tokio::time::timeout(Duration::from_secs(5), handshake_observed).await??;
    }
    if accepted && expect_expiry {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(301)).await;
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(1), observed).await??;
    }
    if let Ok(mut session) = session {
        session.complete().await;
    }
    client
        .close_and_join(RequestDeadline::after(Duration::ZERO)?)
        .await?;
    tokio::time::timeout(Duration::from_secs(5), peer).await???;
    Ok(accepted)
}

#[tokio::test]
async fn downloaded_crls_remain_untrusted_until_native_verification() -> Result<()> {
    let directory = Directory::new()?;
    let good = make_crl(&directory.0, false, false).await?;
    let mut forged = good.clone();
    *forged.last_mut().unwrap() ^= 1;
    let revoked = make_crl(&directory.0, true, false).await?;
    let stale = make_crl(&directory.0, false, true).await?;
    for (body, accepted) in [
        (good, true),
        (revoked, false),
        (forged, false),
        (stale, false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/issuer.crl", listener.local_addr()?);
        let http = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert!(stream.read(&mut [0; 4096]).await? > 0);
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await?;
            stream.write_all(&body).await?;
            Ok::<(), anyhow::Error>(())
        });
        let resolver = HttpCrlResolver::new(
            [HttpCrlSource::new("opaque-crls", [url])?],
            CrlFetchLimits::default(),
        )?;
        assert_eq!(
            probe_with_resolver(&[], true, true, accepted, None, &resolver).await?,
            accepted
        );
        tokio::time::timeout(Duration::from_secs(5), http).await???;
    }
    Ok(())
}

#[tokio::test]
async fn crl_policy_verifies_provider_and_inline_evidence_and_bounds_use() -> Result<()> {
    let directory = Directory::new()?;
    let good = make_crl(&directory.0, false, false).await?;
    for (provider, bundle) in [(false, false), (true, false), (true, true)] {
        assert!(probe(std::slice::from_ref(&good), provider, bundle, true, None).await?);
    }
    let revoked = make_crl(&directory.0, true, false).await?;
    assert!(!probe(&[revoked], true, false, false, None).await?);
    let stale = make_crl(&directory.0, false, true).await?;
    assert!(!probe(&[stale], false, false, false, None).await?);
    let mut forged = good.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(!probe(&[forged], false, false, false, None).await?);
    let mut trailing = good;
    trailing.push(0);
    assert!(!probe(&[trailing], false, false, false, None).await?);
    Ok(())
}

#[tokio::test]
async fn short_peer_with_longer_crl_uses_only_the_evidence_deadline() -> Result<()> {
    let directory = Directory::new()?;
    let crl = make_crl(&directory.0, false, false).await?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let issuer_key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let peer_identity =
        issued_peer_with_lifetime(&issuer, &issuer_key, false, 9090, Some(Duration::from_secs(8)))?;
    let context = peer_context(&issuer, Some(&peer_identity))?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut source = source_for(
        &issuer,
        listener.local_addr()?.port(),
        std::slice::from_ref(&crl),
        false,
        false,
    )?;
    source.server[0].single_connection = true;
    let endpoint = prepare_endpoint(&source.server[0], PrepareOptions::default())?;
    let (handshake_complete, handshake_observed) = tokio::sync::oneshot::channel();
    let (closed, closure_observed) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        Pin::new(&mut stream).accept().await?;
        let _ = handshake_complete.send(());
        super::reply_to_accounting(&mut stream, None, true).await?;
        super::reply_to_accounting(&mut stream, None, false).await?;
        assert_eq!(stream.read(&mut [0_u8; 1]).await?, 0);
        let _ = closed.send(());
        Ok::<_, anyhow::Error>(())
    });
    let client = TacacsClient::connect_prepared(endpoint).await?;
    let first = client.execute(tacacsrs_protocol::exchange::accounting::AccountingExchange::new(
        super::accounting_request(),
    ));
    tokio::pin!(first);
    let (handshake, first) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(handshake_observed, &mut first)
    })
    .await?;
    handshake?;
    first?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let now = openssl::asn1::Asn1Time::from_unix(now.try_into()?)?;
    let remaining = now.diff(peer_identity.certificate.not_after())?;
    let remaining = u64::try_from(remaining.days)? * 86_400 + u64::try_from(remaining.secs)?;
    tokio::time::sleep(Duration::from_secs(remaining + 1)).await;
    tokio::time::timeout(
        Duration::from_secs(3),
        client.execute(tacacsrs_protocol::exchange::accounting::AccountingExchange::new(
            super::accounting_request(),
        )),
    )
    .await??;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(301)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(2), closure_observed).await??;
    if let Err(error) = client
        .close_and_join(RequestDeadline::after(Duration::from_secs(2))?)
        .await
    {
        anyhow::ensure!(
            format!("{error:#}").contains("TLS revocation evidence expired"),
            "unexpected post-evidence-expiry close error: {error:#}"
        );
    }
    tokio::time::timeout(Duration::from_secs(2), peer).await???;
    Ok(())
}

fn issued_peer(
    issuer: &X509,
    issuer_key: &PKey<openssl::pkey::Private>,
    is_ca: bool,
    serial: u32,
) -> Result<PeerIdentity> {
    issued_peer_with_lifetime(issuer, issuer_key, is_ca, serial, None)
}

fn issued_peer_with_lifetime(
    issuer: &X509,
    issuer_key: &PKey<openssl::pkey::Private>,
    is_ca: bool,
    serial: u32,
    lifetime: Option<Duration>,
) -> Result<PeerIdentity> {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::x509::{
        X509NameBuilder,
        extension::{BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName},
    };
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text(
        "CN",
        if is_ca {
            "CRL Intermediate"
        } else {
            "localhost"
        },
    )?;
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_serial_number(
        openssl::bn::BigNum::from_u32(serial)?
            .to_asn1_integer()?
            .as_ref(),
    )?;
    certificate.set_subject_name(&name.build())?;
    certificate.set_issuer_name(issuer.subject_name())?;
    certificate.set_pubkey(&key)?;
    match lifetime {
        Some(lifetime) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            certificate.set_not_before(Asn1Time::from_unix((now - 60).try_into()?)?.as_ref())?;
            certificate.set_not_after(
                Asn1Time::from_unix((now + lifetime.as_secs()).try_into()?)?.as_ref(),
            )?;
        }
        None => {
            certificate.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
            certificate.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        }
    }
    if is_ca {
        certificate.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        certificate.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
    } else {
        certificate.append_extension(BasicConstraints::new().build()?)?;
        certificate.append_extension(KeyUsage::new().digital_signature().build()?)?;
        certificate.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
        let san = SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .dns("localhost")
            .build(&certificate.x509v3_context(Some(issuer), None))?;
        certificate.append_extension(san)?;
    }
    certificate.sign(issuer_key, MessageDigest::sha256())?;
    Ok(PeerIdentity {
        certificate: certificate.build(),
        key,
        chain: Vec::new(),
    })
}

#[tokio::test]
async fn scoped_crls_reject_malformed_scope_even_with_valid_signature() -> Result<()> {
    let directory = Directory::new()?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    for (extensions, preparation_error) in [
        ("issuingDistributionPoint=critical,DER:01:01:FF\n", Some("CRL scope is malformed")),
        ("issuingDistributionPoint=critical,DER:30:03:81:01:FF:00\n", Some("CRL scope must round-trip")),
        ("issuingDistributionPoint=DER:30:03:81:01:FF\n", Some("CRL scope must be critical")),
        ("issuingDistributionPoint=critical,DER:30:03:81:01:FF\n2.5.29.28=critical,DER:30:03:81:01:FF\n", Some("duplicate issuing distribution points")),
        ("issuingDistributionPoint=critical,DER:30:06:81:01:FF:82:01:FF\n", Some("contradictory certificate types")),
        ("issuingDistributionPoint=critical,DER:30:06:81:01:FF:85:01:FF\n", Some("contradictory certificate types")),
        ("issuingDistributionPoint=critical,DER:30:06:82:01:FF:85:01:FF\n", Some("contradictory certificate types")),
        ("issuingDistributionPoint=critical,DER:30:09:81:01:FF:82:01:FF:85:01:FF\n", Some("contradictory certificate types")),
        ("issuingDistributionPoint=critical,DER:30:03:85:01:FF\n", Some("Attribute-certificate CRLs are not supported")),
        ("issuingDistributionPoint=critical,DER:30:03:84:01:FF\n", Some("Indirect CRLs are not supported")),
        ("issuingDistributionPoint=critical,DER:30:03:83:01:00\n", Some("CRL reason flags are empty or unsupported")),
        ("issuingDistributionPoint=critical,DER:30:04:83:02:00:80\n", Some("CRL reason flags are empty or unsupported")),
        ("issuingDistributionPoint=critical,DER:30:05:83:03:06:00:40\n", Some("CRL reason flags are empty or unsupported")),
        ("issuingDistributionPoint=critical,DER:30:06:83:04:00:00:00:80\n", Some("CRL reason flags exceed the supported range")),
    ] {
        let crl = make_extended_crl(&directory.0, &issuer, &key, None, false, Some(extensions)).await?;
        assert!(X509Crl::from_der(&crl)?.verify(&key)?);
        let source = source_for(&issuer, 449, std::slice::from_ref(&crl), false, false)?;
        let prepared = prepare_endpoint(&source.server[0], PrepareOptions::default());
        let expected = preparation_error.expect("every invalid scope case must fail preparation");
        let error = prepared.expect_err("invalid scope must fail before a handshake");
        assert!(format!("{error:#}").contains(expected), "unexpected preparation failure: {error:#}");
        assert!(!probe(&[crl], false, false, false, None).await?, "invalid scope must not become an unscoped CRL: {extensions}");
        assert!(openssl::error::ErrorStack::get().errors().is_empty(), "rejected scope must not leave native errors for later TLS work");
    }
    Ok(())
}

#[tokio::test]
async fn delta_crls_apply_explicit_updates_before_authentication() -> Result<()> {
    let directory = Directory::new()?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let peer = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let base = make_numbered_crl(
        &directory.0,
        &issuer,
        &key,
        None,
        false,
        Some("freshestCRL=URI:http://pki.example.test/delta.crl\n"),
        1,
    )
    .await?;
    let delta = make_numbered_crl(
        &directory.0,
        &issuer,
        &key,
        None,
        false,
        Some("2.5.29.27=critical,DER:02:01:01\n"),
        2,
    )
    .await?;
    let source = source_for(&issuer, 449, &[base.clone(), delta.clone()], false, false)?;
    prepare_endpoint(&source.server[0], PrepareOptions::default())?;
    assert!(probe(&[base.clone(), delta.clone()], true, true, true, None).await?);
    assert!(
        probe(&[delta.clone(), base.clone()], false, false, false, None).await?,
        "input order must not change delta application"
    );
    let revoked_base = make_numbered_crl(
        &directory.0,
        &issuer,
        &key,
        Some(&peer),
        false,
        Some("freshestCRL=URI:http://pki.example.test/delta.crl\n"),
        1,
    )
    .await?;
    assert!(
        !probe(&[delta, revoked_base], true, false, false, None).await?,
        "a clear delta must not erase base revocation"
    );
    let revoked = make_numbered_crl(
        &directory.0,
        &issuer,
        &key,
        Some(&peer),
        false,
        Some("2.5.29.27=critical,DER:02:01:01\n"),
        2,
    )
    .await?;
    assert!(
        !probe(&[base, revoked], true, true, false, None).await?,
        "delta revocation must reject before client authentication"
    );
    Ok(())
}

#[tokio::test]
async fn delta_crls_preserve_direct_certificate_scope() -> Result<()> {
    let directory = Directory::new()?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let peer = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let base = make_numbered_crl(&directory.0, &issuer, &key, None, false,
        Some("freshestCRL=URI:http://pki.example.test/delta.crl\nissuingDistributionPoint=critical,@scope\n[scope]\nonlyuser=TRUE\n"), 1).await?;
    let authorities =
        make_scoped_crl(&directory.0, &issuer, &key, None, false, Some("onlyCA=TRUE\n")).await?;
    for revoked in [false, true] {
        let delta = make_numbered_crl(&directory.0, &issuer, &key, revoked.then_some(&peer), false,
            Some("2.5.29.27=critical,DER:02:01:01\nissuingDistributionPoint=critical,@scope\n[scope]\nonlyuser=TRUE\n"), 2).await?;
        assert_eq!(
            probe(&[authorities.clone(), delta, base.clone()], true, true, !revoked, None).await?,
            !revoked
        );
    }
    Ok(())
}

#[tokio::test]
async fn delta_crls_release_holds_but_full_crls_cannot_remove_revocation() -> Result<()> {
    let directory = Directory::new()?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let peer = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let serial = peer.serial_number().to_bn()?.to_hex_str()?;
    make_numbered_crl(
        &directory.0,
        &issuer,
        &key,
        Some(&peer),
        false,
        Some("freshestCRL=URI:http://pki.example.test/delta.crl\n"),
        1,
    )
    .await?;
    std::fs::write(
        directory.0.join("index.txt"),
        format!("R\t351231235959Z\t200101000000Z,certificateHold\t{serial}\tunknown\t/CN=test\n"),
    )?;
    std::fs::write(directory.0.join("number"), "01\n")?;
    let held = generate_crl(&directory.0, false).await?;
    let clear = make_numbered_crl(
        &directory.0,
        &issuer,
        &key,
        None,
        false,
        Some("2.5.29.27=critical,DER:02:01:01\n"),
        2,
    )
    .await?;
    assert!(!probe(&[held.clone(), clear], false, false, false, None).await?);
    let removal =
        format!("R\t351231235959Z\t200101000000Z,removeFromCRL\t{serial}\tunknown\t/CN=test\n");
    std::fs::write(directory.0.join("index.txt"), &removal)?;
    std::fs::write(directory.0.join("number"), "02\n")?;
    let released = generate_crl(&directory.0, false).await?;
    assert!(probe(&[held, released], true, true, false, None).await?);
    make_issuer_crl(&directory.0, &issuer, &key, None, false).await?;
    std::fs::write(directory.0.join("index.txt"), removal)?;
    std::fs::write(directory.0.join("number"), "01\n")?;
    let invalid = generate_crl(&directory.0, false).await?;
    let source = source_for(&issuer, 449, &[invalid], false, false)?;
    assert!(format!(
        "{:#}",
        prepare_endpoint(&source.server[0], PrepareOptions::default())
            .expect_err("removeFromCRL in full CRL")
    )
    .contains("removeFromCRL requires a delta"));
    Ok(())
}

#[tokio::test]
async fn delta_crls_reject_incomplete_ambiguous_or_unusable_pairs() -> Result<()> {
    let directory = Directory::new()?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let hint = "freshestCRL=URI:http://pki.example.test/delta.crl\n";
    let update = "2.5.29.27=critical,DER:02:01:01\n";
    let base = make_numbered_crl(&directory.0, &issuer, &key, None, false, Some(hint), 1).await?;
    let delta =
        make_numbered_crl(&directory.0, &issuer, &key, None, false, Some(update), 2).await?;
    let duplicate =
        make_numbered_crl(&directory.0, &issuer, &key, None, false, Some(update), 3).await?;
    let plain = make_issuer_crl(&directory.0, &issuer, &key, None, false).await?;
    for lists in [
        vec![base.clone()],
        vec![delta.clone()],
        vec![plain, delta.clone()],
        vec![base.clone(), delta.clone(), duplicate],
    ] {
        let source = source_for(&issuer, 449, &lists, false, false)?;
        assert!(
            prepare_endpoint(&source.server[0], PrepareOptions::default()).is_err(),
            "incomplete or ambiguous delta set"
        );
    }
    for (extension, number) in [(update, Some(1)), ("2.5.29.27=critical,DER:02:01:03\n", Some(4)), (update, None),
        ("2.5.29.27=critical,DER:02:01:01\nauthorityKeyIdentifier=DER:30:03:80:01:01\n", Some(2)),
        ("2.5.29.27=critical,DER:02:01:01\nissuingDistributionPoint=critical,DER:30:03:81:01:FF\n", Some(2))] {
        let candidate = make_numbered_crl(&directory.0, &issuer, &key, None, false, Some(extension), number).await?;
        let source = source_for(&issuer, 449, &[base.clone(), candidate], false, false)?;
        assert!(prepare_endpoint(&source.server[0], PrepareOptions::default()).is_err(), "invalid pairing must fail preparation");
    }
    let mut forged_delta = delta.clone();
    *forged_delta.last_mut().unwrap() ^= 1;
    assert!(!probe(&[base.clone(), forged_delta], false, false, false, None).await?);
    let mut forged_base = base.clone();
    *forged_base.last_mut().unwrap() ^= 1;
    assert!(!probe(&[forged_base, delta.clone()], false, false, false, None).await?);
    let stale = make_numbered_crl(&directory.0, &issuer, &key, None, true, Some(update), 2).await?;
    let source = source_for(&issuer, 449, &[base, stale], false, false)?;
    assert!(format!(
        "{:#}",
        prepare_endpoint(&source.server[0], PrepareOptions::default()).expect_err("stale delta")
    )
    .contains("CRL is stale"));
    let stale_base =
        make_numbered_crl(&directory.0, &issuer, &key, None, true, Some(hint), 1).await?;
    let source = source_for(&issuer, 449, &[stale_base, delta], false, false)?;
    assert!(format!(
        "{:#}",
        prepare_endpoint(&source.server[0], PrepareOptions::default()).expect_err("stale base")
    )
    .contains("CRL is stale"));
    Ok(())
}

#[tokio::test]
async fn delta_crls_reject_malformed_metadata_before_native_verification() -> Result<()> {
    let directory = Directory::new()?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    for (extension, expected) in [
        ("2.5.29.27=DER:02:01:01\n", "criticality"),
        ("2.5.29.27=critical,DER:01:01:FF\n", "Malformed CRL number"),
        ("2.5.29.27=critical,DER:02:01:01:00\n", "round-trip"),
        ("2.5.29.27=critical,DER:02:01:FF\n", "nonnegative"),
        ("freshestCRL=critical,URI:http://pki.example.test/delta\n", "noncritical"),
        ("freshestCRL=DER:01:01:FF\n", "Malformed CRL authority or freshest"),
        ("freshestCRL=DER:30:00\n", "Freshest CRL extension is empty"),
        ("authorityKeyIdentifier=DER:01:01:FF\n", "Malformed CRL authority or freshest"),
        ("2.5.29.27=critical,DER:02:01:01\nfreshestCRL=URI:http://pki.example.test/delta\n", "Delta CRLs cannot contain"),
        ("freshestCRL=URI:http://pki.example.test/delta\nissuingDistributionPoint=critical,@scope\n[scope]\nonlysomereasons=keyCompromise\n", "reason flags"),
    ] {
        let candidate = make_numbered_crl(&directory.0, &issuer, &key, None, false, Some(extension), 2).await?;
        assert!(X509Crl::from_der(&candidate)?.verify(&key)?);
        let source = source_for(&issuer, 449, &[candidate], false, false)?;
        let error = prepare_endpoint(&source.server[0], PrepareOptions::default()).expect_err("invalid delta metadata");
        assert!(format!("{error:#}").contains(expected), "unexpected rejection: {error:#}");
        assert!(openssl::error::ErrorStack::get().errors().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn certificate_type_crls_for_one_issuer_cover_the_whole_path() -> Result<()> {
    let directory = Directory::new()?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let end_entities =
        make_scoped_crl(&directory.0, &issuer, &key, None, false, Some("onlyuser=TRUE\n")).await?;
    let authorities =
        make_scoped_crl(&directory.0, &issuer, &key, None, false, Some("onlyCA=TRUE\n")).await?;
    let source =
        source_for(&issuer, 449, &[end_entities.clone(), authorities.clone()], false, false)?;
    prepare_endpoint(&source.server[0], PrepareOptions::default())?;
    assert!(probe(&[end_entities.clone(), authorities.clone()], true, true, true, None).await?);
    assert!(probe(&[authorities.clone(), end_entities.clone()], false, false, false, None).await?);
    let unrestricted = make_issuer_crl(&directory.0, &issuer, &key, None, false).await?;
    for lists in [
        vec![
            end_entities.clone(),
            authorities.clone(),
            end_entities.clone(),
        ],
        vec![
            authorities.clone(),
            end_entities.clone(),
            authorities.clone(),
        ],
        vec![unrestricted.clone(), end_entities.clone()],
        vec![authorities.clone(), unrestricted],
    ] {
        let source = source_for(&issuer, 449, &lists, false, false)?;
        assert!(
            prepare_endpoint(&source.server[0], PrepareOptions::default()).is_err(),
            "overlapping scope sets must fail preparation"
        );
    }
    let partial_authorities = make_scoped_crl(
        &directory.0,
        &issuer,
        &key,
        None,
        false,
        Some("onlyCA=TRUE\nonlysomereasons=keyCompromise\n"),
    )
    .await?;
    assert!(
        !probe(&[end_entities.clone(), partial_authorities.clone()], true, true, false, None)
            .await?,
        "end-entity reasons must not fill missing authority reasons"
    );
    let remaining_authorities = make_scoped_crl(&directory.0, &issuer, &key, None, false,
        Some("onlyCA=TRUE\nonlysomereasons=CACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold,privilegeWithdrawn,AACompromise\n")).await?;
    assert!(
        probe(
            &[
                partial_authorities,
                end_entities.clone(),
                remaining_authorities
            ],
            true,
            true,
            false,
            None
        )
        .await?,
        "reason partitions must accumulate within their certificate-type group"
    );
    let peer = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let revoked_peer =
        make_scoped_crl(&directory.0, &issuer, &key, Some(&peer), false, Some("onlyuser=TRUE\n"))
            .await?;
    assert!(!probe(&[authorities.clone(), revoked_peer], false, false, false, None).await?);
    let revoked_authority =
        make_scoped_crl(&directory.0, &issuer, &key, Some(&issuer), false, Some("onlyCA=TRUE\n"))
            .await?;
    assert!(!probe(&[end_entities.clone(), revoked_authority], false, false, false, None).await?);
    assert!(
        !probe(&[end_entities], false, false, false, None).await?,
        "missing authority coverage must fail"
    );
    assert!(
        !probe(&[authorities], false, false, false, None).await?,
        "missing end-entity coverage must fail"
    );
    Ok(())
}

#[tokio::test]
async fn reason_partitioned_crls_require_complete_coverage() -> Result<()> {
    let directory = Directory::new()?;
    let root = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let intermediate = issued_peer(&root, &key, true, 530)?;
    let mut leaf = issued_peer(&intermediate.certificate, &intermediate.key, false, 531)?;
    leaf.chain.push(intermediate.certificate.clone());
    let root_crl = make_issuer_crl(&directory.0, &root, &key, None, false).await?;
    let first = make_scoped_crl(
        &directory.0,
        &intermediate.certificate,
        &intermediate.key,
        None,
        false,
        Some("onlyuser=TRUE\nonlysomereasons=keyCompromise\n"),
    )
    .await?;
    let second = make_scoped_crl(&directory.0, &intermediate.certificate, &intermediate.key, None, false,
        Some("onlyuser=TRUE\nonlysomereasons=CACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold,privilegeWithdrawn,AACompromise\n")).await?;
    let source =
        source_for(&root, 449, &[first.clone(), second.clone(), root_crl.clone()], false, false)?;
    prepare_endpoint(&source.server[0], PrepareOptions::default())?;
    assert!(
        probe(&[first.clone(), second.clone(), root_crl.clone()], true, true, true, Some(&leaf))
            .await?,
        "complementary reason partitions must provide complete issuer evidence"
    );
    assert!(
        probe(&[second.clone(), root_crl.clone(), first.clone()], true, false, false, Some(&leaf))
            .await?,
        "input order must not select different coverage"
    );
    for lists in [
        vec![first.clone(), first.clone()],
        vec![second.clone(), second.clone()],
    ] {
        let source = source_for(&root, 449, &lists, false, false)?;
        assert!(format!(
            "{:#}",
            prepare_endpoint(&source.server[0], PrepareOptions::default())
                .expect_err("duplicate partition")
        )
        .contains("overlap or repeat"));
    }
    let wrong_scope = make_scoped_crl(
        &directory.0,
        &intermediate.certificate,
        &intermediate.key,
        None,
        false,
        Some("onlyuser=TRUE\nfullname=URI:http://pki.example.test/other.crl\nonlysomereasons=CACompromise\n"),
    )
    .await?;
    let source = source_for(&root, 449, &[first.clone(), wrong_scope], false, false)?;
    assert!(format!(
        "{:#}",
        prepare_endpoint(&source.server[0], PrepareOptions::default()).expect_err("mixed scope")
    )
    .contains("same scope"));
    let revoked = make_scoped_crl(&directory.0, &intermediate.certificate, &intermediate.key, Some(&leaf.certificate), false,
        Some("onlyuser=TRUE\nonlysomereasons=CACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold,privilegeWithdrawn,AACompromise\n")).await?;
    assert!(
        !probe(&[first.clone(), revoked, root_crl.clone()], true, true, false, Some(&leaf)).await?,
        "revocation in the later partition must fail"
    );
    let mut forged = second.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(
        !probe(&[first.clone(), forged, root_crl.clone()], false, false, false, Some(&leaf))
            .await?,
        "each contributing partition needs a valid signature"
    );
    let source = source_for(&root, 449, &vec![root_crl.clone(); 129], false, false)?;
    assert!(format!(
        "{:#}",
        prepare_endpoint(&source.server[0], PrepareOptions::default()).expect_err("too many CRLs")
    )
    .contains("128-list limit"));
    assert!(!probe(&[first, root_crl.clone()], true, false, false, Some(&leaf)).await?);
    assert!(!probe(&[second, root_crl], true, false, false, Some(&leaf)).await?);
    Ok(())
}

#[tokio::test]
async fn scoped_crls_enforce_certificate_type_and_complete_path_coverage() -> Result<()> {
    let directory = Directory::new()?;
    let root = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let intermediate = issued_peer(&root, &key, true, 510)?;
    let mut leaf = issued_peer(&intermediate.certificate, &intermediate.key, false, 511)?;
    leaf.chain.push(intermediate.certificate.clone());
    let root_crl =
        make_scoped_crl(&directory.0, &root, &key, None, false, Some("onlyCA=TRUE\n")).await?;
    for (scope, accepted) in [
        ("onlyuser=TRUE\n", true),
        ("onlyCA=TRUE\n", false),
        ("onlyAA=TRUE\n", false),
        ("onlysomereasons=keyCompromise\n", false),
    ] {
        let scoped = make_scoped_crl(
            &directory.0,
            &intermediate.certificate,
            &intermediate.key,
            None,
            false,
            Some(scope),
        )
        .await?;
        assert_eq!(
            probe(&[scoped, root_crl.clone()], true, true, false, Some(&leaf)).await?,
            accepted,
            "{scope}"
        );
    }
    let scoped = make_scoped_crl(
        &directory.0,
        &intermediate.certificate,
        &intermediate.key,
        None,
        false,
        Some("onlyuser=TRUE\n"),
    )
    .await?;
    let mut forged = scoped.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(
        !probe(&[forged, root_crl.clone()], false, false, false, Some(&leaf)).await?,
        "scoped evidence still requires a valid signature"
    );
    assert!(
        !probe(&[scoped], false, false, false, Some(&leaf)).await?,
        "leaf coverage cannot replace missing CA evidence"
    );
    let revoked = make_scoped_crl(
        &directory.0,
        &intermediate.certificate,
        &intermediate.key,
        Some(&leaf.certificate),
        false,
        Some("onlyuser=TRUE\n"),
    )
    .await?;
    assert!(
        !probe(&[revoked, root_crl], false, false, false, Some(&leaf)).await?,
        "scope does not override a revoked leaf"
    );
    Ok(())
}

async fn add_distribution_point(
    directory: &Path,
    identity: &mut PeerIdentity,
    issuer: &X509,
    key: &PKey<openssl::pkey::Private>,
) -> Result<()> {
    let mut request = openssl::x509::X509Req::builder()?;
    request.set_subject_name(identity.certificate.subject_name())?;
    request.set_pubkey(&identity.key)?;
    request.sign(&identity.key, openssl::hash::MessageDigest::sha256())?;
    std::fs::write(directory.join("scope-peer.pem"), request.build().to_pem()?)?;
    std::fs::write(directory.join("scope-issuer.pem"), issuer.to_pem()?)?;
    std::fs::write(directory.join("scope-key.pem"), key.private_key_to_pem_pkcs8()?)?;
    std::fs::write(directory.join("scope.cnf"), "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\ncrlDistributionPoints=URI:http://pki.example.test/leaf.crl\n")?;
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("openssl")
            .kill_on_drop(true)
            .args(["x509", "-req", "-in"])
            .arg(directory.join("scope-peer.pem"))
            .arg("-CA")
            .arg(directory.join("scope-issuer.pem"))
            .arg("-CAkey")
            .arg(directory.join("scope-key.pem"))
            .args(["-set_serial", "521", "-days", "1", "-extfile"])
            .arg(directory.join("scope.cnf"))
            .output(),
    )
    .await??;
    anyhow::ensure!(
        output.status.success(),
        "Scoped certificate generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    identity.certificate = X509::from_pem(&output.stdout)?;
    Ok(())
}

#[tokio::test]
async fn scoped_crls_require_matching_distribution_points_and_bound_lifetime() -> Result<()> {
    let directory = Directory::new()?;
    let root = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let intermediate = issued_peer(&root, &key, true, 520)?;
    let mut leaf = issued_peer(&intermediate.certificate, &intermediate.key, false, 521)?;
    add_distribution_point(&directory.0, &mut leaf, &intermediate.certificate, &intermediate.key)
        .await?;
    leaf.chain.push(intermediate.certificate.clone());
    let root_crl = make_issuer_crl(&directory.0, &root, &key, None, false).await?;
    for (scope, accepted) in [
        ("fullname=URI:http://pki.example.test/leaf.crl\nonlyuser=TRUE\n", true),
        ("fullname=URI:http://pki.example.test/other.crl\nonlyuser=TRUE\n", false),
    ] {
        let scoped = make_scoped_crl(
            &directory.0,
            &intermediate.certificate,
            &intermediate.key,
            None,
            false,
            Some(scope),
        )
        .await?;
        assert_eq!(
            probe(&[scoped, root_crl.clone()], true, true, accepted, Some(&leaf)).await?,
            accepted,
            "{scope}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn crl_policy_rejects_revoked_intermediates_and_incomplete_evidence() -> Result<()> {
    let directory = Directory::new()?;
    let root = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    let intermediate = issued_peer(&root, &key, true, 500)?;
    let mut leaf = issued_peer(&intermediate.certificate, &intermediate.key, false, 501)?;
    leaf.chain.push(intermediate.certificate.clone());
    let issuer_crl =
        make_issuer_crl(&directory.0, &intermediate.certificate, &intermediate.key, None, false)
            .await?;
    let root_crl = make_issuer_crl(&directory.0, &root, &key, None, false).await?;
    assert!(probe(&[issuer_crl.clone(), root_crl.clone()], true, false, false, Some(&leaf)).await?);
    assert!(
        !probe(&[root_crl], false, false, false, Some(&leaf)).await?,
        "missing leaf issuer CRL must fail closed"
    );
    let revoked =
        make_issuer_crl(&directory.0, &root, &key, Some(&intermediate.certificate), false).await?;
    assert!(
        !probe(&[issuer_crl, revoked], true, false, false, Some(&leaf)).await?,
        "revoked intermediate must fail before client authentication"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn crl_expiry_withdraws_supervised_catalog_without_source_failure() -> Result<()> {
    use std::sync::Arc;
    use tacacsrs_agent::{
        EnabledServices, RuntimeHealthPublisher, ServiceConfig, TacacsClientService,
        DegradationReason,
    };
    use tacacsrs_agent::runtime::{ConfigSupervisor, NoopTacacsPlusFilter};
    use tacacsrs_config::source::{ConfigDatastore, StaticDatastore};
    tokio::time::resume();
    let directory = Directory::new()?;
    let crl = make_crl(&directory.0, false, false).await?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let source = source_for(&issuer, 449, &[crl], false, false)?;
    let original = source.clone();
    let datastore = Arc::new(StaticDatastore::new(source));
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = Arc::new(TacacsClientService::waiting_for_configuration(
        ServiceConfig {
            local_services: tacacsrs_config::tacacsrs::LocalServices::default(),
            tacacs_plus: TacacsPlus::empty(),
            validation_options: ValidationOptions::default(),
            runtime_policy: tacacsrs_agent::RuntimePolicy::default(),
            disable_certificate_verification: false,
        },
        health.clone(),
    )?);
    let mut supervisor = ConfigSupervisor::new(
        datastore.clone(),
        service.clone(),
        health.clone(),
        Arc::new(NoopTacacsPlusFilter::default()),
    );
    supervisor.initialize_until(std::future::pending()).await?;
    assert_eq!(service.server_count(), 1);
    let cancellation = tokio_util::sync::CancellationToken::new();
    let monitor = supervisor.run_until(cancellation.cancelled());
    tokio::pin!(monitor);
    assert!(futures_util::poll!(&mut monitor).is_pending());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(301)).await;
    assert!(futures_util::poll!(&mut monitor).is_pending());
    assert_eq!(service.server_count(), 0);
    assert!(health
        .snapshot()
        .degradation_reasons()
        .contains(&DegradationReason::CredentialsExpired));
    assert_eq!(health.snapshot().datastore(), tacacsrs_agent::DatastoreState::Current);
    assert_eq!(datastore.load().await?, original);
    cancellation.cancel();
    monitor.await?;
    Ok(())
}

async fn stalled_accounting_peer(
    listener: TcpListener,
    context: SslContext,
    received: tokio::sync::oneshot::Sender<()>,
    closed: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    use tacacsrs_networking::{PacketReadResult, PacketReader};
    let (tcp, _) = listener.accept().await?;
    let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
    Pin::new(&mut stream).accept().await?;
    assert!(matches!(
        PacketReader::new(None).read_packet(&mut stream).await,
        PacketReadResult::Success(_)
    ));
    let _ = received.send(());
    match stream.read(&mut [0]).await {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        result => anyhow::bail!("unexpected application data after CRL refresh: {result:?}"),
    }
    let _ = closed.send(());
    Ok(())
}

#[tokio::test]
async fn committed_crl_refresh_interrupts_active_peer_without_waiting_for_request_budget(
) -> Result<()> {
    use std::sync::Arc;
    use tacacsrs_agent::{RuntimeHealthPublisher, RuntimeLifecycle, ServiceConfig, TacacsClientService};
    use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
    use tacacsrs_protocol::operations::AccountingOperation;
    let directory = Directory::new()?;
    let good = make_crl(&directory.0, false, false).await?;
    let revoked = make_crl(&directory.0, true, false).await?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let context = peer_context(&issuer, None)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let source = source_for(&issuer, listener.local_addr()?.port(), &[good], false, false)?;
    let path = directory.0.join("agent.sock");
    let endpoint = IpcEndpoint::Unix(path.clone());
    let config = ServiceConfig {
        local_services: tacacsrs_config::tacacsrs::LocalServices {
            client_api_enabled: true,
            client_api_endpoint: path.display().to_string(),
            ..Default::default()
        },
        tacacs_plus: source.clone(),
        validation_options: ValidationOptions::default(),
        runtime_policy: tacacsrs_agent::RuntimePolicy::default(),
        disable_certificate_verification: false,
    };
    let health = RuntimeHealthPublisher::new(config.enabled_services());
    let service = Arc::new(TacacsClientService::new(config, health.clone())?);
    let (received, observed) = tokio::sync::oneshot::channel();
    let (closed, mut closure) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(stalled_accounting_peer(listener, context, received, closed));
    let stop = tokio_util::sync::CancellationToken::new();
    let running = service.clone();
    let shutdown = stop.clone();
    let listeners = crate::client_api::client_api_listeners(&service);
    let serving =
        tokio::spawn(async move { running.serve_until(shutdown.cancelled(), listeners).await });
    tokio::time::timeout(
        Duration::from_secs(5),
        health
            .subscribe()
            .wait_for(|snapshot| snapshot.lifecycle() == RuntimeLifecycle::Serving),
    )
    .await??;
    let client = ServiceClient::connect(endpoint).await?;
    let request = client.send_accounting(AccountingOperation {
        user: "refresh".to_owned(),
        port: "test".to_owned(),
        remote_address: "127.0.0.1".to_owned(),
        command: "show".to_owned(),
        command_arguments: Vec::new(),
    });
    tokio::pin!(request);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! { result = &mut request => panic!("request ended before peer received it: {result:?}"), result = observed => result.unwrap() }
    }).await?;
    service.reload_tacacs_plus(source.clone()).await?;
    let mut ordinary = source.clone();
    ordinary.server[0].timeout += 1;
    service.reload_tacacs_plus(ordinary).await?;
    let before_rejection = health.snapshot().runtime_generation();
    let mut invalid = source.clone();
    invalid.server[0]
        .server_authentication
        .as_mut()
        .unwrap()
        .require_crls
        .as_mut()
        .unwrap()
        .crl = Some(vec![b"invalid-crl".to_vec()]);
    assert!(service.reload_tacacs_plus(invalid).await.is_err());
    assert_eq!(health.snapshot().runtime_generation(), before_rejection);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut closure)
            .await
            .is_err(),
        "unchanged evidence, ordinary reload, or rejected evidence must not close the active peer"
    );
    let mut updated = source;
    updated.server[0]
        .server_authentication
        .as_mut()
        .unwrap()
        .require_crls
        .as_mut()
        .unwrap()
        .crl = Some(vec![revoked]);
    service.reload_tacacs_plus(updated).await?;
    let closed_promptly = tokio::time::timeout(Duration::from_secs(1), closure).await;
    stop.cancel();
    let result = tokio::time::timeout(Duration::from_secs(5), request).await?;
    assert!(result.is_err());
    tokio::time::timeout(Duration::from_secs(5), serving).await???;
    tokio::time::timeout(Duration::from_secs(5), peer).await???;
    assert!(
        closed_promptly.is_ok(),
        "committed CRL changes must not retain the ordinary request drain budget"
    );
    Ok(())
}
