//! Bounded HTTP/1.1 CRL downloads.
//!
//! A fetch uses the TCP connection that [`RevocationNetwork::connect`] opens, so
//! it keeps the local binding and host guard of the TACACS+ server. The fetch
//! follows no redirects and stops reading when the body exceeds the size limit.

use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, ensure};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONTENT_LENGTH, HOST, USER_AGENT};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tacacsrs_networking::{DistributionPointUrl, RevocationNetwork};

const AGENT: &str = concat!("tacacsrs-revocation/", env!("CARGO_PKG_VERSION"));

/// Aborts the HTTP connection driver when the fetch ends.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Downloads `url` and returns at most `limit` body bytes.
///
/// The caller applies the time limit.
pub(crate) async fn fetch(
    url: &DistributionPointUrl,
    network: &RevocationNetwork,
    filter: &(dyn Fn(SocketAddr) -> Result<()> + Send + Sync),
    limit: u64,
) -> Result<Bytes> {
    let stream = network
        .connect(url.host(), url.port(), filter)
        .await
        .with_context(|| format!("Could not connect to CRL distribution point {url}"))?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
            .await
            .context("HTTP handshake failed")?;
    let _driver = AbortOnDrop(tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::debug!("CRL HTTP connection ended: {error}");
        }
    }));
    let request = Request::get(url.path())
        .header(HOST, authority(url))
        .header(USER_AGENT, AGENT)
        .header(ACCEPT, "application/pkix-crl, application/x-pkcs7-crl, */*")
        .body(Empty::<Bytes>::new())
        .context("Could not build a CRL request")?;
    let response = sender
        .send_request(request)
        .await
        .with_context(|| format!("CRL request to {url} failed"))?;
    let status = response.status();
    ensure!(status == StatusCode::OK, "CRL distribution point {url} returned HTTP status {status}");
    if let Some(length) = response.headers().get(CONTENT_LENGTH) {
        let length: u64 = length
            .to_str()
            .ok()
            .and_then(|text| text.parse().ok())
            .context("Invalid Content-Length")?;
        ensure!(
            length <= limit,
            "CRL from {url} has {length} bytes, more than the {limit}-byte limit"
        );
    }
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let body = Limited::new(response.into_body(), limit)
        .collect()
        .await
        .map_err(|error| anyhow!("Could not read the CRL from {url}: {error}"))?
        .to_bytes();
    Ok(body)
}

fn authority(url: &DistributionPointUrl) -> String {
    let host = url.host();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if url.port() == 80 {
        host
    } else {
        format!("{host}:{}", url.port())
    }
}
