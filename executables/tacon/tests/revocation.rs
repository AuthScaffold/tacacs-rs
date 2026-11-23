use std::path::Path;
use std::process::Output;
use std::time::Duration;

use openssl::sha::sha256;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;

use tacacsrs_protocol::accounting::reply::AccountingReply;
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_protocol::constants::TACACS_HEADER_LENGTH;
use tacacsrs_protocol::enumerations::{TacacsAccountingStatus, TacacsFlags, TacacsType};
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::Packet;
use tacacsrs_testkit::pki::TestIdentity;

const CRL_URL: &str = "http://127.0.0.1/root.crl";

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

fn server_context(authority: &TestIdentity, server: &TestIdentity) -> SslContext {
    let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
    context.set_certificate(server.certificate()).unwrap();
    context.set_private_key(server.private_key()).unwrap();
    context
        .cert_store_mut()
        .add_cert(authority.certificate().clone())
        .unwrap();
    context.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    context.build()
}

async fn serve_accounting(listener: TcpListener, context: SslContext) -> anyhow::Result<bool> {
    let (tcp, _) = listener.accept().await?;
    let mut stream = tokio_openssl::SslStream::new(Ssl::new(&context)?, tcp)?;
    if std::pin::Pin::new(&mut stream).accept().await.is_err() {
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
    authority: &TestIdentity,
    client: &TestIdentity,
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
                        &client.private_key_pkcs8_der().unwrap()
                    ),
                    "cert-data": openssl::base64::encode_block(&client.certificate_der().unwrap())
                }}},
                "server-authentication": {"ca-certs": {"inline-definition": {
                    "certificate": [{
                        "name": "test-ca",
                        "cert-data": openssl::base64::encode_block(
                            &authority.certificate_der().unwrap()
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
    let authority = TestIdentity::new_ca("Test Root", 1).unwrap();
    let server = authority
        .issue_server("Test Server", 2, Some(CRL_URL))
        .unwrap();
    let client = authority.issue_client("Test Client", 3).unwrap();
    let context = server_context(&authority, &server);
    let valid_crl = authority.sign_crl(1, None).unwrap();
    let revoked_crl = authority.sign_crl(1, Some(&server)).unwrap();
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
