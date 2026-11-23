use std::path::Path;
use std::pin::Pin;
use std::process::Output;
use std::time::Duration;

use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage,
    SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509CrlBuilder, X509Extension, X509NameBuilder, X509RevokedBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;

use tacacsrs_protocol::accounting::reply::AccountingReply;
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_protocol::constants::TACACS_HEADER_LENGTH;
use tacacsrs_protocol::enumerations::{TacacsAccountingStatus, TacacsFlags, TacacsType};
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::Packet;

const CRL_URL: &str = "http://127.0.0.1/root.crl";

struct Identity {
    certificate: X509,
    key: PKey<Private>,
}

fn identity(name: &str, serial: u32, issuer: Option<&Identity>, server: bool) -> Identity {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_nid(Nid::COMMONNAME, name)
        .unwrap();
    let name = name_builder.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate
        .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate
        .set_issuer_name(issuer.map_or(name.as_ref(), |issuer| issuer.certificate.subject_name()))
        .unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    if issuer.is_none() {
        certificate
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        certificate
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let identifier = SubjectKeyIdentifier::new()
            .build(&certificate.x509v3_context(None, None))
            .unwrap();
        certificate.append_extension(identifier).unwrap();
    } else {
        let mut usage = ExtendedKeyUsage::new();
        if server {
            usage.server_auth();
            let names = SubjectAlternativeName::new()
                .ip("127.0.0.1")
                .build(&certificate.x509v3_context(None, None))
                .unwrap();
            certificate.append_extension(names).unwrap();
            let uri = der(0x86, CRL_URL.as_bytes());
            let full_name = der(0xa0, &uri);
            let point = der(0xa0, &full_name);
            let points = der(0x30, &der(0x30, &point));
            let extension = X509Extension::new_from_der(
                &Asn1Object::from_str("2.5.29.31").unwrap(),
                false,
                &Asn1OctetString::new_from_bytes(&points).unwrap(),
            )
            .unwrap();
            certificate.append_extension(extension).unwrap();
        } else {
            usage.client_auth();
        }
        certificate
            .append_extension(usage.build().unwrap())
            .unwrap();
    }
    certificate
        .sign(issuer.map_or(&key, |issuer| &issuer.key), MessageDigest::sha256())
        .unwrap();
    Identity {
        certificate: certificate.build(),
        key,
    }
}

fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut result = vec![tag, u8::try_from(value.len()).unwrap()];
    result.extend_from_slice(value);
    result
}

fn signed_crl(authority: &Identity, server: &Identity, revoked: bool) -> Vec<u8> {
    let mut crl = X509CrlBuilder::new().unwrap();
    crl.set_issuer_name(authority.certificate.subject_name())
        .unwrap();
    crl.set_last_update(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    crl.set_next_update(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let builder = X509::builder().unwrap();
    let context = builder.x509v3_context(Some(&authority.certificate), None);
    crl.append_extension(
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&context)
            .unwrap(),
    )
    .unwrap();
    crl.append_extension(
        CrlNumber::new(BigNum::from_u32(1).unwrap())
            .unwrap()
            .build()
            .unwrap(),
    )
    .unwrap();
    if revoked {
        let mut entry = X509RevokedBuilder::new().unwrap();
        entry
            .set_serial_number(server.certificate.serial_number())
            .unwrap();
        entry
            .set_revocation_date(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        crl.add_revoked(entry.build()).unwrap();
    }
    crl.sign(&authority.key, MessageDigest::sha256()).unwrap();
    crl.build().unwrap().to_der().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn cache_crl(directory: &Path, crl: &[u8]) {
    std::fs::create_dir(directory).unwrap();
    let name = format!("{}.crl", hex(&sha256(CRL_URL.as_bytes())));
    let mut contents =
        format!("tacacsrs-crl 1\nurl {CRL_URL}\nsha256 {}\n\n", hex(&sha256(crl))).into_bytes();
    contents.extend_from_slice(crl);
    std::fs::write(directory.join(name), contents).unwrap();
}

fn server_context(authority: &Identity, server: &Identity) -> SslContext {
    let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
    context.set_certificate(&server.certificate).unwrap();
    context.set_private_key(&server.key).unwrap();
    context
        .cert_store_mut()
        .add_cert(authority.certificate.clone())
        .unwrap();
    context.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    context.build()
}

async fn serve_accounting(listener: TcpListener, context: SslContext) -> anyhow::Result<bool> {
    let (tcp, _) = listener.accept().await?;
    let mut stream = tokio_openssl::SslStream::new(Ssl::new(&context)?, tcp)?;
    if Pin::new(&mut stream).accept().await.is_err() {
        return Ok(false);
    }
    assert!(stream.ssl().peer_certificate().is_some(), "mTLS requires a client certificate");
    let mut bytes = [0; TACACS_HEADER_LENGTH];
    stream.read_exact(&mut bytes).await?;
    let mut header = Header::from_bytes(&bytes)?;
    assert_eq!(header.tacacs_type, TacacsType::TacPlusAccounting);
    let mut request = vec![0; usize::try_from(header.length)?];
    stream.read_exact(&mut request).await?;
    let body = AccountingReply {
        status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
        server_msg: String::new(),
        data: String::new(),
    }
    .to_bytes()?;
    header.seq_no += 1;
    header.flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
    header.length = u32::try_from(body.len())?;
    stream
        .write_all(&Packet::new(header, body)?.to_bytes())
        .await?;
    Ok(true)
}

async fn run_tacon(
    authority: &Identity,
    client: &Identity,
    context: &SslContext,
    enforcement: &str,
    batch: bool,
    dedicated: bool,
    crl: Option<&[u8]>,
) -> (Output, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(serve_accounting(listener, context.clone()));
    let directory = tempfile::tempdir().unwrap();
    let mut config = serde_json::json!({
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [{
                "name": "test-server",
                "server-type": "accounting",
                "address": address.ip().to_string(),
                "port": address.port(),
                "client-identity": {"certificate": {"inline-definition": {
                    "private-key-format": "ietf-crypto-types:one-asymmetric-key-format",
                    "cleartext-private-key": openssl::base64::encode_block(
                        &client.key.private_key_to_pkcs8().unwrap()
                    ),
                    "cert-data": openssl::base64::encode_block(&client.certificate.to_der().unwrap())
                }}},
                "server-authentication": {"ca-certs": {"inline-definition": {
                    "certificate": [{
                        "name": "test-ca",
                        "cert-data": openssl::base64::encode_block(
                            &authority.certificate.to_der().unwrap()
                        )
                    }]
                }}}
            }],
            "tacacsrs:certificate-revocation": {
                "enforcement": enforcement,
                "allowed-distribution-point": ["http://127.0.0.1/**"]
            }
        }
    });
    if let Some(crl) = crl {
        let cache = directory.path().join("crls");
        cache_crl(&cache, crl);
        config["ietf-system-tacacs-plus:tacacs-plus"]["tacacsrs:certificate-revocation"]
            ["cache-directory"] = cache.to_string_lossy().into_owned().into();
    }
    let config_path = directory.path().join("config.json");
    std::fs::write(&config_path, config.to_string()).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_tacon"));
    command.kill_on_drop(true).arg("--config").arg(config_path);
    if dedicated {
        command.arg("--dedicated");
    }
    if batch {
        let batch_path = directory.path().join("batch.json");
        std::fs::write(
            &batch_path,
            r#"{"requests":[{"type":"accounting","user":"alice","port":"tty0","rem_addr":"192.0.2.1","cmd":"show"}]}"#,
        )
        .unwrap();
        command.arg("batch").arg(batch_path);
    } else {
        command.args([
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.1",
            "show",
        ]);
    }
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .expect("tacon did not exit")
        .unwrap();
    let handshake = tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .expect("the TLS peer did not exit")
        .unwrap()
        .unwrap();
    (output, handshake)
}

#[tokio::test]
async fn configured_revocation_controls_single_and_batch_mtls_commands() {
    let authority = identity("Test Root", 1, None, false);
    let server = identity("Test Server", 2, Some(&authority), true);
    let client = identity("Test Client", 3, Some(&authority), false);
    let context = server_context(&authority, &server);
    let valid_crl = signed_crl(&authority, &server, false);
    let revoked_crl = signed_crl(&authority, &server, true);
    for (enforcement, batch, dedicated, crl, accepted) in [
        ("disabled", false, false, None, true),
        ("hard-fail", false, false, None, false),
        ("warn-only", false, true, None, true),
        ("hard-fail", true, false, None, false),
        ("disabled", true, true, None, true),
        ("hard-fail", false, false, Some(valid_crl.as_slice()), true),
        ("hard-fail", true, true, Some(valid_crl.as_slice()), true),
        ("hard-fail", false, false, Some(revoked_crl.as_slice()), false),
        ("warn-only", true, true, Some(revoked_crl.as_slice()), false),
    ] {
        let (output, handshake) =
            run_tacon(&authority, &client, &context, enforcement, batch, dedicated, crl).await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.success(),
            accepted,
            "enforcement={enforcement} batch={batch} dedicated={dedicated}\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(handshake, accepted, "unexpected mTLS handshake outcome for {enforcement}");
        if !accepted {
            assert!(
                stdout.contains("revocation") || stderr.contains("revocation"),
                "the command must report the revocation error: {stdout}\n{stderr}"
            );
        }
    }
}
