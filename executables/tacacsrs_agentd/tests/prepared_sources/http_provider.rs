use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::Result;
use openssl::{pkey::PKey, x509::X509};
use openssl::ssl::{Ssl, SslContext, SslMethod};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio_openssl::SslStream;
use tonic_health::pb::health_check_response::ServingStatus;

use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_agent_client::health::{HealthClient, READINESS_HEALTH_SERVICE};

use super::crl_peer::{make_crl, source_for};
use super::ocsp_peer::{Directory, fixtures};

fn agent_command(directory: &Path, url: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tacacsrs-agentd"));
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .arg("--config")
        .arg(directory.join("config.json"))
        .arg("--runtime-policy")
        .arg(directory.join("policy.json"))
        .arg("--listen-endpoint")
        .arg(directory.join("agent.sock"))
        .args([
            "--host-integration",
            "none",
            "--http-crl-source",
            "opaque-crls",
            url,
        ]);
    command
}

async fn write_source(directory: &Path) -> Result<Vec<u8>> {
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    let source = source_for(&issuer, 449, &[], true, true)?;
    let mut value = serde_json::to_value(&source)?;
    let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("client.key"))?)?
        .private_key_to_pkcs8()?;
    value["server"][0]["client-identity"]["certificate"]["inline-definition"]
        ["cleartext-private-key"] = serde_json::Value::String(openssl::base64::encode_block(&key));
    let bytes =
        serde_json::to_vec(&serde_json::json!({"ietf-system-tacacs-plus:tacacs-plus": value}))?;
    assert_eq!(tacacsrs_config::parse_yang_json(std::str::from_utf8(&bytes)?)?, source);
    tokio::fs::write(directory.join("config.json"), &bytes).await?;
    tokio::fs::write(directory.join("policy.json"), br#"{"tacacsrs:runtime-policy":{"credential-refresh-interval-seconds":1,"credential-stale-timeout-seconds":1,"shutdown-timeout-seconds":1}}"#).await?;
    Ok(bytes)
}

async fn wait_for_health(
    directory: &Path,
    child: &mut Child,
    expected: ServingStatus,
) -> Result<()> {
    let endpoint = IpcEndpoint::Unix(directory.join("agent.sock"));
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            anyhow::ensure!(child.try_wait()?.is_none(), "daemon exited before expected readiness");
            if let Ok(mut client) = HealthClient::connect(&endpoint).await {
                if client.check(READINESS_HEALTH_SERVICE).await.ok() == Some(expected) {
                    return Ok::<(), anyhow::Error>(());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    Ok(())
}

async fn terminate(child: Child) -> Result<()> {
    assert!(Command::new("kill")
        .arg("-TERM")
        .arg(child.id().unwrap().to_string())
        .status()
        .await?
        .success());
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
    assert!(
        output.status.success(),
        "daemon shutdown failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[tokio::test]
async fn daemon_http_loads_a_complete_delta_pair_without_rewriting_source() -> Result<()> {
    for complete in [true, false] {
        let directory = Directory::new()?;
        let original = write_source(&directory.0).await?;
        let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
        let key = PKey::private_key_from_pem(&std::fs::read(fixtures().join("ca.key"))?)?;
        let base = super::crl_peer::make_numbered_crl(
            &directory.0,
            &issuer,
            &key,
            None,
            false,
            Some("freshestCRL=URI:http://pki.example.test/delta.crl\n"),
            1,
        )
        .await?;
        let delta = super::crl_peer::make_numbered_crl(
            &directory.0,
            &issuer,
            &key,
            None,
            false,
            Some("2.5.29.27=critical,DER:02:01:01\n"),
            2,
        )
        .await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base_url = format!("http://{}/base.crl", listener.local_addr()?);
        let delta_url = format!("http://{}/delta.crl", listener.local_addr()?);
        let peer = tokio::spawn(async move {
            for (path, body) in [("/base.crl", base), ("/delta.crl", delta)] {
                let (mut stream, _) = listener.accept().await?;
                let mut request = [0; 4096];
                let length = stream.read(&mut request).await?;
                assert!(String::from_utf8_lossy(&request[..length])
                    .starts_with(&format!("GET {path} ")));
                if path == "/delta.crl" && !complete {
                    stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                } else {
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await?;
                    stream.write_all(&body).await?;
                }
            }
            Ok::<(), anyhow::Error>(())
        });
        let mut child = agent_command(&directory.0, &base_url)
            .args(["--http-crl-source", "opaque-crls", &delta_url])
            .spawn()?;
        if complete {
            wait_for_health(&directory.0, &mut child, ServingStatus::Serving).await?;
            terminate(child).await?;
        } else {
            let output =
                tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
            assert!(!output.status.success());
            assert!(!directory.0.join("agent.sock").exists());
        }
        tokio::time::timeout(Duration::from_secs(5), peer).await???;
        assert_eq!(tokio::fs::read(directory.0.join("config.json")).await?, original);
    }
    Ok(())
}

#[tokio::test]
async fn daemon_http_refresh_withdraws_recovers_and_cancels_pending_io() -> Result<()> {
    let directory = Directory::new()?;
    let original = write_source(&directory.0).await?;
    let body = make_crl(&directory.0, false, false).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/issuer.crl", listener.local_addr()?);
    let mode = Arc::new(AtomicU8::new(0));
    let peer_mode = mode.clone();
    let (events, mut observed) = tokio::sync::watch::channel((0u8, 0usize));
    let (closed, closure) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let mut count = 0;
        loop {
            let (mut stream, _) = listener.accept().await?;
            assert!(stream.read(&mut [0; 4096]).await? > 0);
            let current = peer_mode.load(Ordering::SeqCst);
            count += 1;
            events.send_replace((current, count));
            if current == 2 {
                assert_eq!(stream.read(&mut [0]).await?, 0);
                let _ = closed.send(());
                break;
            }
            if current == 0 {
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                stream.write_all(&body).await?;
            } else {
                stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut child = agent_command(&directory.0, &url).spawn()?;
    wait_for_health(&directory.0, &mut child, ServingStatus::Serving).await?;
    tokio::time::timeout(Duration::from_secs(5), observed.wait_for(|&(_, count)| count >= 2))
        .await??;
    mode.store(1, Ordering::SeqCst);
    wait_for_health(&directory.0, &mut child, ServingStatus::NotServing).await?;
    mode.store(0, Ordering::SeqCst);
    wait_for_health(&directory.0, &mut child, ServingStatus::Serving).await?;
    assert_eq!(tokio::fs::read(directory.0.join("config.json")).await?, original);
    mode.store(2, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), observed.wait_for(|&(mode, _)| mode == 2))
        .await??;
    terminate(child).await?;
    tokio::time::timeout(Duration::from_secs(1), closure).await??;
    tokio::time::timeout(Duration::from_secs(1), peer).await???;
    assert!(!directory.0.join("agent.sock").exists());
    Ok(())
}

#[tokio::test]
async fn daemon_http_startup_failure_and_cancellation_do_not_bind_ipc() -> Result<()> {
    for cancel in [false, true] {
        let directory = Directory::new()?;
        write_source(&directory.0).await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/issuer.crl", listener.local_addr()?);
        let child = agent_command(&directory.0, &url).spawn()?;
        let (mut stream, _) =
            tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
        assert!(stream.read(&mut [0; 4096]).await? > 0);
        if cancel {
            terminate(child).await?;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0])).await??,
                0
            );
        } else {
            stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            let output =
                tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
            assert!(!output.status.success());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(!error.contains(&url) && !error.contains("opaque-crls"));
        }
        assert!(!directory.0.join("agent.sock").exists());
    }
    Ok(())
}

#[tokio::test]
async fn daemon_https_requires_trusted_ca_and_matching_identity() -> Result<()> {
    for (trusted, address, accepted) in [
        (true, "127.0.0.1:0", true),
        (false, "127.0.0.1:0", false),
        (true, "127.0.0.2:0", false),
    ] {
        let directory = Directory::new()?;
        write_source(&directory.0).await?;
        let body = make_crl(&directory.0, false, false).await?;
        let empty_trust = directory.0.join("empty.pem");
        tokio::fs::write(&empty_trust, b"").await?;
        let mut context = SslContext::builder(SslMethod::tls_server())?;
        context.set_certificate(
            X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?.as_ref(),
        )?;
        context.set_private_key(
            PKey::private_key_from_pem(&std::fs::read(fixtures().join("server.key"))?)?.as_ref(),
        )?;
        let context = context.build();
        let listener = TcpListener::bind(address).await?;
        let url = format!("https://{}/issuer.crl", listener.local_addr()?);
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = SslStream::new(Ssl::new(&context)?, stream)?;
            let handshake = Pin::new(&mut stream).accept().await;
            if !accepted {
                assert!(handshake.is_err(), "untrusted or mismatched HTTPS identity must fail TLS");
                return Ok::<(), anyhow::Error>(());
            }
            handshake?;
            assert!(stream.read(&mut [0; 4096]).await? > 0);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&body).await?;
            Ok(())
        });
        let mut child = agent_command(&directory.0, &url)
            .env(
                "SSL_CERT_FILE",
                if trusted {
                    fixtures().join("ca.crt")
                } else {
                    empty_trust
                },
            )
            .env("SSL_CERT_DIR", &directory.0)
            .spawn()?;
        if accepted {
            wait_for_health(&directory.0, &mut child, ServingStatus::Serving).await?;
            terminate(child).await?;
        } else {
            let output =
                tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
            assert!(!output.status.success());
            assert!(!String::from_utf8_lossy(&output.stderr).contains(&url));
            assert!(!directory.0.join("agent.sock").exists());
        }
        tokio::time::timeout(Duration::from_secs(5), peer).await???;
    }
    Ok(())
}
