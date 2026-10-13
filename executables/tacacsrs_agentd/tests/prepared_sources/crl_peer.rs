use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVersion, SslVerifyMode};
use openssl::x509::{X509, X509Crl};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

use tacacsrs_config::{TacacsPlus, TacacsPlusServerBuilder, TacacsPlusServerType, ValidationOptions};
use tacacsrs_config::prepare::{enumerate_materialized_servers, prepare_endpoint, PrepareOptions};
use tacacsrs_credential_resolution::{
    CertificateRevocationListsMaterial, CredentialValidity, FakeCredentialResolver, PublicBytes,
    RequestSlot, ResolvedCredential,
};
use tacacsrs_networking::{RequestDeadline, TacacsClient};

use super::ocsp_peer::{Directory, fixtures};

async fn make_crl(directory: &Path, revoked: bool, stale: bool) -> Result<Vec<u8>> {
    let peer = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
    make_issuer_crl(directory, &issuer, &key, revoked.then_some(&peer), stale).await
}

async fn make_issuer_crl(
    directory: &Path,
    issuer: &X509,
    key: &PKey<openssl::pkey::Private>,
    revoked: Option<&X509>,
    stale: bool,
) -> Result<Vec<u8>> {
    let index = match revoked {
        Some(peer) => format!(
            "R\t351231235959Z\t200101000000Z\t{}\tunknown\t/CN=test\n",
            peer.serial_number().to_bn()?.to_hex_str()?
        ),
        None => String::new(),
    };
    std::fs::write(directory.join("index.txt"), index)?;
    std::fs::write(directory.join("number"), "01\n")?;
    std::fs::write(directory.join("issuer.pem"), issuer.to_pem()?)?;
    std::fs::write(directory.join("issuer.key"), key.private_key_to_pem_pkcs8()?)?;
    let configuration = format!("[ca]\ndefault_ca=issuer\n[issuer]\ndatabase={}\ncertificate={}\nprivate_key={}\ndefault_md=sha256\ndefault_crl_days=1\ncrlnumber={}\n", directory.join("index.txt").display(), directory.join("issuer.pem").display(), directory.join("issuer.key").display(), directory.join("number").display());
    std::fs::write(directory.join("ca.cnf"), configuration)?;
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

fn source_for(
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
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let context = peer_context(&issuer, identity)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let source = source_for(&issuer, listener.local_addr()?.port(), lists, provider, bundle)?;
    let original = source.clone();
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
    let materialized =
        enumerate_materialized_servers(&source, &resolver, &ValidationOptions::default()).await?;
    let endpoint = prepare_endpoint(materialized[0].server(), PrepareOptions::default());
    assert_eq!(source, original);
    let Ok(endpoint) = endpoint else {
        return Ok(false);
    };
    assert!(endpoint.prepared_credential_validity().is_some());
    let (closed, observed) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        if Pin::new(&mut stream).accept().await.is_ok() {
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
    let client = TacacsClient::connect_prepared(endpoint).await?;
    let session = client.open_conversation().await;
    let accepted = session.is_ok();
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

fn issued_peer(
    issuer: &X509,
    issuer_key: &PKey<openssl::pkey::Private>,
    is_ca: bool,
    serial: u32,
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
    certificate.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    certificate.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
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
