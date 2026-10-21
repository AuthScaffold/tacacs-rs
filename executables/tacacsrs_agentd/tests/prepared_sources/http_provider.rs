use std::future::{Future, poll_fn};
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use openssl::{pkey::PKey, x509::X509};
use openssl::ssl::{Ssl, SslContext, SslMethod};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio_openssl::SslStream;
use tonic_health::pb::health_check_response::ServingStatus;

use tacacsrs_ipc::IpcEndpoint;
use tacacsrs_ipc::health::{HealthClient, READINESS_HEALTH_SERVICE};

use super::crl_peer::{make_crl, source_for};
use super::ocsp_peer::{Directory, fixtures};

const FIXTURE_HEADER_LIMIT: u64 = 16 * 1024;
const FIXTURE_BODY_LIMIT: u64 = 64 * 1024;

async fn read_fixture_request(
    reader: &mut (impl AsyncBufRead + Unpin),
    expected_line: &str,
    deadline: tokio::time::Instant,
) -> Result<bool> {
    tokio::time::timeout_at(deadline, async {
        ensure!(
            matches!(expected_line, "GET /issuer.crl HTTP/1.1" | "POST /ocsp HTTP/1.1"),
            "unsupported fixture request"
        );
        let mut headers = (&mut *reader).take(FIXTURE_HEADER_LIMIT);
        let mut line = Vec::new();
        let mut request_line = true;
        let mut content_length = None;
        loop {
            ensure!(headers.limit() > 0, "fixture headers exceed limit");
            line.clear();
            headers.read_until(b'\n', &mut line).await.context("read fixture headers")?;
            let complete = line.ends_with(b"\n");
            let text = if complete {
                ensure!(line.ends_with(b"\r\n"), "fixture line lacks CRLF");
                &line[..line.len() - 2]
            } else {
                ensure!(headers.limit() > 0, "fixture headers exceed limit");
                line.strip_suffix(b"\r").unwrap_or(&line)
            };
            // EOF can cut a line, but the bytes already received must still be valid.
            let truncated = !complete && text.len() == line.len();
            let valid_name = |name: &[u8]| {
                !name.is_empty()
                    && name.iter().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte)
                    })
            };
            if request_line {
                ensure!(
                    text == expected_line.as_bytes()
                        || truncated && expected_line.as_bytes().starts_with(text),
                    "unexpected fixture request line"
                );
                request_line = false;
            } else if text.is_empty() {
                if complete {
                    break;
                }
            } else if truncated && !text.contains(&b':') {
                ensure!(valid_name(text), "invalid fixture header name");
            } else {
                let (name, value) = std::str::from_utf8(text)?
                    .split_once(':')
                    .context("fixture header lacks colon")?;
                ensure!(valid_name(name.as_bytes()), "invalid fixture header name");
                ensure!(
                    value.bytes().all(|byte| byte == b'\t' || (32..127).contains(&byte)),
                    "invalid fixture header value"
                );
                ensure!(
                    !["transfer-encoding", "expect", "trailer", "upgrade"]
                        .iter()
                        .any(|header| name.eq_ignore_ascii_case(header)),
                    "unsupported fixture framing header: {name}"
                );
                if complete && name.eq_ignore_ascii_case("content-length") {
                    ensure!(content_length.is_none(), "duplicate fixture Content-Length");
                    let value = value.trim_matches([' ', '\t']);
                    ensure!(
                        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
                        "invalid fixture Content-Length"
                    );
                    let length: u64 =
                        value.parse().context("overflow in fixture Content-Length")?;
                    ensure!(length <= FIXTURE_BODY_LIMIT, "fixture body exceeds limit");
                    content_length = Some(length);
                }
            }
            if !complete {
                eprintln!("fixture incomplete EOF: {expected_line}; line_bytes={}", line.len());
                return Ok(false);
            }
        }
        let header_bytes = FIXTURE_HEADER_LIMIT - headers.limit();
        let body_length = if expected_line.starts_with("POST ") {
            content_length.context("fixture POST lacks Content-Length")?
        } else {
            ensure!(content_length.unwrap_or(0) == 0, "fixture GET has a body");
            0
        };
        let body_bytes = tokio::io::copy(
            &mut (&mut *reader).take(body_length),
            &mut tokio::io::sink(),
        )
        .await
        .context("read fixture body")?;
        if body_bytes != body_length {
            eprintln!("fixture incomplete body EOF: {body_bytes}/{body_length}");
            return Ok(false);
        }
        eprintln!(
            "fixture complete: {expected_line}; header_bytes={header_bytes}; Content-Length={content_length:?}; body_bytes={body_bytes}"
        );
        Ok(true)
    })
    .await.context("fixture request deadline elapsed")?
}

async fn wait_fixture_eof(
    reader: &mut (impl AsyncBufRead + Unpin),
    pending: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    let mut byte = [0];
    let read = reader.read(&mut byte);
    tokio::pin!(read);
    let initial = poll_fn(|context| Poll::Ready(read.as_mut().poll(context))).await;
    ensure!(initial.is_pending(), "fixture EOF read was not pending: {initial:?}");
    assert!(pending.send(()).is_ok());
    ensure!(
        read.await.context("read fixture cancellation EOF")? == 0,
        "unexpected bytes after fixture body"
    );
    eprintln!("fixture observed EOF after pending barrier");
    Ok(())
}

#[tokio::test]
async fn fixture_reader_empty_connection_is_incomplete() -> Result<()> {
    let (client, server) = tokio::io::duplex(1);
    drop(client);
    assert!(
        !read_fixture_request(
            &mut BufReader::new(server),
            "GET /issuer.crl HTTP/1.1",
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn fixture_reader_fragmented_ocsp_request() -> Result<()> {
    let (mut client, server) = tokio::io::duplex(1);
    client.write_all(b"P").await?;
    let mut reader = BufReader::new(server);
    let (request, written) = tokio::join!(
        read_fixture_request(
            &mut reader,
            "POST /ocsp HTTP/1.1",
            tokio::time::Instant::now() + Duration::from_secs(1),
        ),
        client.write_all(b"OST /ocsp HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"),
    );
    written?;
    assert!(request?);
    Ok(())
}

#[tokio::test]
async fn fixture_reader_counts_only_complete_requests_and_waits_for_close() -> Result<()> {
    let (mut client, server) = tokio::io::duplex(256);
    let mut reader = BufReader::new(server);
    let count = std::sync::atomic::AtomicUsize::new(0);
    {
        let request = async {
            if read_fixture_request(
                &mut reader,
                "POST /ocsp HTTP/1.1",
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await?
            {
                count.fetch_add(1, Ordering::SeqCst);
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::pin!(request);
        for fragment in [
            b"POST /oc".as_slice(),
            b"sp HTTP/1.1\r",
            b"\ncOnTeNt-LeNgTh:\t3 \r",
            b"\nX-Test: value\r\n\r",
            b"\na",
            b"b",
        ] {
            client.write_all(fragment).await?;
            assert!(poll_fn(|context| Poll::Ready(request.as_mut().poll(context)))
                .await
                .is_pending());
            assert_eq!(count.load(Ordering::SeqCst), 0);
        }
        client.write_all(b"c").await?;
        request.await?;
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let (pending, mut observed) = tokio::sync::oneshot::channel();
    let closed = wait_fixture_eof(&mut reader, pending);
    tokio::pin!(closed);
    assert!(poll_fn(|context| Poll::Ready(closed.as_mut().poll(context)))
        .await
        .is_pending());
    assert_eq!(observed.try_recv(), Ok(()));
    client.shutdown().await?;
    closed.await?;
    Ok(())
}

#[tokio::test]
async fn fixture_reader_cancelled_connections_do_not_count_or_stop_the_loop() -> Result<()> {
    let mut count = 0;
    for (bytes, complete) in [
        (b"".as_slice(), false),
        (b"P", false),
        (b"POST /ocsp HTTP/1.1\r", false),
        (b"POST /ocsp HTTP/1.1\r\nContent-Length: 3\r\n\r", false),
        (b"POST /ocsp HTTP/1.1\r\nContent-Length: 3\r\n\r\nab", false),
        (b"POST /ocsp HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc", true),
    ] {
        let received = read_fixture_request(
            &mut BufReader::new(bytes),
            "POST /ocsp HTTP/1.1",
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await?;
        assert_eq!(received, complete);
        if !received {
            assert_eq!(count, 0);
            continue;
        }
        count += 1;
    }
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn fixture_reader_rejects_malformed_truncated_requests() -> Result<()> {
    for (bytes, diagnostic) in [
        (b"GET /ocsp".as_slice(), "unexpected fixture request line"),
        (b"POST /ocsp HTTP/1.1\rX", "unexpected fixture request line"),
        (b"POST /ocsp HTTP/1.1\r\nTransfer-Encoding: chu", "unsupported fixture framing"),
        (b"POST /ocsp HTTP/1.1\r\nBad Name: x", "invalid fixture header name"),
        (b"POST /ocsp HTTP/1.1\r\nContent-Length 3\r", "lacks colon"),
        (b"POST /ocsp HTTP/1.1\r\nX-Test: \0", "invalid fixture header value"),
    ] {
        let error = read_fixture_request(
            &mut BufReader::new(bytes),
            "POST /ocsp HTTP/1.1",
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains(diagnostic), "{error:#}");
    }
    Ok(())
}

#[tokio::test]
async fn fixture_reader_rejects_invalid_framing_and_buffered_extra_bytes() -> Result<()> {
    for (headers, diagnostic) in [
        ("", "POST lacks Content-Length"),
        ("Content-Length: 0\r\ncontent-length: 0\r\n", "duplicate"),
        ("Content-Length: \r\n", "invalid fixture Content-Length"),
        ("Content-Length: +1\r\n", "invalid fixture Content-Length"),
        ("Content-Length: -1\r\n", "invalid fixture Content-Length"),
        ("Content-Length: 1, 1\r\n", "invalid fixture Content-Length"),
        ("Content-Length: 18446744073709551616\r\n", "overflow"),
        ("Content-Length: 65537\r\n", "body exceeds limit"),
        ("Transfer-Encoding: chunked\r\n", "unsupported fixture framing"),
        ("Content-Length: 0\r\ntRaNsFeR-EnCoDiNg: identity\r\n", "unsupported fixture framing"),
        ("Expect: 100-continue\r\n", "unsupported fixture framing"),
        ("Trailer: Content-Length\r\n", "unsupported fixture framing"),
        ("Upgrade: websocket\r\n", "unsupported fixture framing"),
        ("Content-Length : 0\r\n", "invalid fixture header name"),
        ("Content-Length 0\r\n", "lacks colon"),
        ("X-Test: \0\r\n", "invalid fixture header value"),
    ] {
        let bytes = format!("POST /ocsp HTTP/1.1\r\n{headers}\r\n");
        let error = read_fixture_request(
            &mut bytes.as_bytes(),
            "POST /ocsp HTTP/1.1",
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains(diagnostic), "{error:#}");
    }
    for bytes in [
        "POST /issuer.crl HTTP/1.1\r\n\r\n".to_owned(),
        "GET /wrong HTTP/1.1\r\n\r\n".to_owned(),
        "GET /issuer.crl HTTP/1.0\r\n\r\n".to_owned(),
        "GET /issuer.crl HTTP/1.1\n\n".to_owned(),
        "GET /issuer.crl HTTP/1.1\r\nContent-Length: 1\r\n\r\na".to_owned(),
        "a".repeat(FIXTURE_HEADER_LIMIT.try_into()?),
        format!("GET /issuer.crl HTTP/1.1\r\n{}\r\n", "X: y\r\n".repeat(3000)),
    ] {
        assert!(read_fixture_request(
            &mut bytes.as_bytes(),
            "GET /issuer.crl HTTP/1.1",
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .is_err());
    }
    for bytes in [
        b"GET /issuer.crl HTTP/1.1\r\n\r\nextra".as_slice(),
        b"GET /issuer.crl HTTP/1.1\r\ncontent-length: 0\r\n\r\nextra",
        b"POST /ocsp HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcextra",
    ] {
        let mut reader = BufReader::new(bytes);
        let expected_line = if bytes.starts_with(b"GET") {
            "GET /issuer.crl HTTP/1.1"
        } else {
            "POST /ocsp HTTP/1.1"
        };
        assert!(
            read_fixture_request(
                &mut reader,
                expected_line,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await?
        );
        let (pending, mut observed) = tokio::sync::oneshot::channel();
        assert!(wait_fixture_eof(&mut reader, pending).await.is_err());
        assert!(observed.try_recv().is_err());
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn fixture_reader_fragments_do_not_renew_the_deadline() -> Result<()> {
    let (mut client, server) = tokio::io::duplex(256);
    let mut reader = BufReader::new(server);
    let request = read_fixture_request(
        &mut reader,
        "POST /ocsp HTTP/1.1",
        tokio::time::Instant::now() + Duration::from_secs(1),
    );
    tokio::pin!(request);
    client.write_all(b"POST /ocsp HTTP/1.1\r").await?;
    assert!(poll_fn(|context| Poll::Ready(request.as_mut().poll(context)))
        .await
        .is_pending());
    tokio::time::advance(Duration::from_millis(900)).await;
    client.write_all(b"\nContent-Length: 3\r\n\r\nab").await?;
    assert!(poll_fn(|context| Poll::Ready(request.as_mut().poll(context)))
        .await
        .is_pending());
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(request
        .await
        .unwrap_err()
        .is::<tokio::time::error::Elapsed>());
    Ok(())
}

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
async fn daemon_online_ocsp_refreshes_recovers_and_cancels_without_source_edits() -> Result<()> {
    let directory = Directory::new()?;
    let source = write_source(&directory.0).await?;
    let mut source: serde_json::Value = serde_json::from_slice(&source)?;
    let bundle = source["ietf-system-tacacs-plus:tacacs-plus"]["server-credentials"][0]
        .as_object_mut()
        .unwrap();
    bundle.remove("tacacsrs:require-crls");
    bundle.insert(
        "tacacsrs:require-ocsp".to_owned(),
        serde_json::json!({"evidence-reference":"online"}),
    );
    let original = serde_json::to_vec(&source)?;
    tacacsrs_config::parse_yang_json(std::str::from_utf8(&original)?)?;
    tokio::fs::write(directory.0.join("config.json"), &original).await?;
    let certificate = X509::from_pem(&std::fs::read(fixtures().join("server.crt"))?)?;
    let issuer = X509::from_pem(&std::fs::read(fixtures().join("ca.crt"))?)?;
    tokio::fs::write(directory.0.join("peer.der"), certificate.to_der()?).await?;
    tokio::fs::write(directory.0.join("issuer.der"), issuer.to_der()?).await?;
    let body =
        super::ocsp_peer::signed_response(&directory.0, &certificate, "good", Some(1440)).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/ocsp", listener.local_addr()?);
    let mode = Arc::new(AtomicU8::new(0));
    let peer_mode = mode.clone();
    let (events, mut observed) = tokio::sync::watch::channel((0u8, 0usize));
    let (pending, pending_request) = tokio::sync::oneshot::channel();
    let (closed, mut closure) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let mut count = 0;
        loop {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            if !read_fixture_request(
                &mut stream,
                "POST /ocsp HTTP/1.1",
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await?
            {
                continue;
            }
            let mode = peer_mode.load(Ordering::SeqCst);
            count += 1;
            events.send_replace((mode, count));
            if mode == 2 {
                wait_fixture_eof(&mut stream, pending).await?;
                assert!(closed.send(()).is_ok());
                break;
            }
            if mode == 1 {
                stream.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            } else {
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await?;
                stream.write_all(&body).await?;
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut child = agent_command(&directory.0, &url)
        .args(["--http-ocsp-source", "online", &url])
        .arg(directory.0.join("peer.der"))
        .arg(directory.0.join("issuer.der"))
        .spawn()?;
    wait_for_health(&directory.0, &mut child, ServingStatus::Serving).await?;
    tokio::time::timeout(Duration::from_secs(5), observed.wait_for(|&(_, count)| count >= 2))
        .await??;
    mode.store(1, Ordering::SeqCst);
    wait_for_health(&directory.0, &mut child, ServingStatus::NotServing).await?;
    mode.store(0, Ordering::SeqCst);
    wait_for_health(&directory.0, &mut child, ServingStatus::Serving).await?;
    mode.store(2, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), observed.wait_for(|&(mode, _)| mode == 2))
        .await??;
    tokio::time::timeout(Duration::from_secs(5), pending_request).await??;
    assert_eq!(closure.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty));
    terminate(child).await?;
    tokio::time::timeout(Duration::from_secs(1), closure).await??;
    tokio::time::timeout(Duration::from_secs(1), peer).await???;
    assert_eq!(tokio::fs::read(directory.0.join("config.json")).await?, original);
    assert!(!directory.0.join("agent.sock").exists());
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
    let (pending, pending_request) = tokio::sync::oneshot::channel();
    let (closed, mut closure) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let mut count = 0;
        loop {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            if !read_fixture_request(
                &mut stream,
                "GET /issuer.crl HTTP/1.1",
                tokio::time::Instant::now() + Duration::from_secs(5),
            )
            .await?
            {
                continue;
            }
            let current = peer_mode.load(Ordering::SeqCst);
            count += 1;
            events.send_replace((current, count));
            if current == 2 {
                wait_fixture_eof(&mut stream, pending).await?;
                assert!(closed.send(()).is_ok());
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
    tokio::time::timeout(Duration::from_secs(5), pending_request).await??;
    assert_eq!(closure.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty));
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
