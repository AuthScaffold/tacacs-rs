//! TLS handshakes through the networking crate with an injected [`CrlVerifier`].
//!
//! Each test runs a real OpenSSL server and a local CRL server. The client is a
//! [`TacacsClient`] that opens one conversation, which runs the TLS handshake.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use openssl::ssl::{Ssl, SslContext, SslMethod};
use tokio::net::TcpListener;
use tokio::sync::watch;

use tacacsrs_networking::{
    CertificateTrust, CertificateVerification, ConnectOptions, DistributionPointPattern,
    DistributionPointUrl, PreparedEndpoint, PreparedTransport, RevocationEnforcement,
    RevocationNetwork, RevocationSettings, StatisticsSnapshot, TacacsClient, TlsClientConfig,
};

use super::pki::{CertificateOptions, CrlOptions, Issued, crl, issue, key};
use super::server::{Response, Server, closed_url};
use crate::CrlVerifier;

const CRL: &str = "/root.crl";

struct Peer {
    root: Issued,
    leaf: Issued,
}

impl Peer {
    fn new(point: &str) -> Self {
        let root = issue(
            "Handshake Root",
            key(),
            None,
            &CertificateOptions {
                ca: true,
                serial: 1,
                ..CertificateOptions::default()
            },
        );
        let leaf = issue(
            "localhost",
            key(),
            Some(&root),
            &CertificateOptions {
                serial: 7,
                distribution_points: &[point],
                dns_names: &["localhost"],
                ..CertificateOptions::default()
            },
        );
        Self { root, leaf }
    }

    fn crl(&self, revoked: bool) -> Vec<u8> {
        let listed = [&self.leaf.certificate];
        crl(
            &self.root,
            &CrlOptions {
                revoked: if revoked {
                    &listed
                } else {
                    &[]
                },
                ..CrlOptions::default()
            },
        )
    }

    /// Accepts TLS handshakes until the test ends.
    async fn serve(&self) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
        context.set_certificate(&self.leaf.certificate).unwrap();
        context.set_private_key(&self.leaf.key).unwrap();
        context.set_num_tickets(0).unwrap();
        let context = context.build();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let ssl = Ssl::new(&context).unwrap();
                tokio::spawn(async move {
                    let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
                    if Pin::new(&mut stream).accept().await.is_ok() {
                        // Keep the connection until the client closes it.
                        let mut buffer = [0_u8; 64];
                        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
                    }
                });
            }
        });
        address
    }
}

fn settings(enforcement: RevocationEnforcement, pattern: &str) -> RevocationSettings {
    let mut settings = RevocationSettings::default();
    settings.enforcement = enforcement;
    settings.allowed_distribution_points = vec![DistributionPointPattern::parse(pattern).unwrap()];
    settings.fetch_timeout = Duration::from_secs(2);
    settings
}

/// Opens one conversation and returns its result with the endpoint counters.
async fn handshake(
    peer: &Peer,
    address: std::net::SocketAddr,
    verifier: &CrlVerifier,
) -> (anyhow::Result<()>, StatisticsSnapshot) {
    let anchor = peer.root.certificate.to_der().unwrap();
    let config = TlsClientConfig::prepare(
        "localhost",
        None,
        CertificateTrust::Certificates {
            authorities: &[&anchor],
            end_entities: &[],
        },
        None,
        CertificateVerification::Required,
    )
    .unwrap();
    let endpoint = PreparedEndpoint::new(
        address.try_into().unwrap(),
        PreparedTransport::Tls(config),
        false,
        None,
        ConnectOptions::default().with_timeout(Duration::from_secs(5)),
    )
    .with_revocation_verifier(Arc::new(verifier.clone()));
    let counters = endpoint.counters();
    let result = async {
        let client = TacacsClient::connect_prepared(endpoint).await?;
        client.open_conversation().await.map(drop)
    }
    .await;
    (result, counters.snapshot())
}

#[tokio::test]
async fn hard_fail_rejects_a_listed_server_certificate() {
    let server = Server::start().await;
    let peer = Peer::new(&server.url(CRL));
    server.route(CRL, Response::Body(peer.crl(true)));
    let (_sender, receiver) =
        watch::channel(settings(RevocationEnforcement::HardFail, &server.pattern()));
    let verifier = CrlVerifier::with_loopback(receiver);
    let address = peer.serve().await;

    let (result, snapshot) = handshake(&peer, address, &verifier).await;
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("revoked"), "{error}");
    assert_eq!(snapshot.diagnostics.tls_revoked_certificates, 1);
    assert_eq!(snapshot.diagnostics.revocation_evidence_waits, 1);
}

#[tokio::test]
async fn hard_fail_accepts_an_unlisted_certificate_and_reuses_the_crl() {
    let server = Server::start().await;
    let peer = Peer::new(&server.url(CRL));
    server.route(CRL, Response::Body(peer.crl(false)));
    let (_sender, receiver) =
        watch::channel(settings(RevocationEnforcement::HardFail, &server.pattern()));
    let verifier = CrlVerifier::with_loopback(receiver);
    let address = peer.serve().await;

    for _ in 0..3 {
        let (result, snapshot) = handshake(&peer, address, &verifier).await;
        result.unwrap();
        assert_eq!(snapshot.diagnostics.tls_certificate_errors, 0);
    }
    assert_eq!(server.requests(CRL), 1, "later handshakes must use the cached CRL");
}

#[tokio::test]
async fn hard_fail_rejects_when_evidence_is_unavailable() {
    let point = closed_url(CRL).await;
    let peer = Peer::new(&point);
    let pattern = format!("{}/**", point.trim_end_matches(CRL));
    let (_sender, receiver) = watch::channel(settings(RevocationEnforcement::HardFail, &pattern));
    let verifier = CrlVerifier::with_loopback(receiver);
    let address = peer.serve().await;

    let (result, snapshot) = handshake(&peer, address, &verifier).await;
    assert!(result.is_err());
    assert_eq!(snapshot.diagnostics.tls_certificate_errors, 1);
    assert_eq!(snapshot.diagnostics.tls_revoked_certificates, 0);
}

#[tokio::test]
async fn warn_only_accepts_missing_evidence_but_rejects_a_listed_certificate() {
    let point = closed_url(CRL).await;
    let peer = Peer::new(&point);
    let pattern = format!("{}/**", point.trim_end_matches(CRL));
    let (_sender, receiver) = watch::channel(settings(RevocationEnforcement::WarnOnly, &pattern));
    let verifier = CrlVerifier::with_loopback(receiver);
    let address = peer.serve().await;
    let (result, snapshot) = handshake(&peer, address, &verifier).await;
    result.unwrap();
    assert_eq!(snapshot.diagnostics.revocation_unverified_accepts, 1);

    let server = Server::start().await;
    let peer = Peer::new(&server.url(CRL));
    server.route(CRL, Response::Body(peer.crl(true)));
    let (_sender, receiver) =
        watch::channel(settings(RevocationEnforcement::WarnOnly, &server.pattern()));
    let verifier = CrlVerifier::with_loopback(receiver);
    let address = peer.serve().await;
    let (result, snapshot) = handshake(&peer, address, &verifier).await;
    assert!(result.is_err(), "warn-only must still reject a listed certificate");
    assert_eq!(snapshot.diagnostics.tls_revoked_certificates, 1);
}

#[tokio::test]
async fn prefetched_crl_avoids_a_handshake_wait() {
    let server = Server::start().await;
    let peer = Peer::new(&server.url(CRL));
    server.route(CRL, Response::Body(peer.crl(false)));
    let mut policy = settings(RevocationEnforcement::HardFail, &server.pattern());
    policy.prefetch_distribution_points =
        vec![DistributionPointUrl::parse(&server.url(CRL)).unwrap()];
    let (_sender, receiver) = watch::channel(policy);
    let verifier = CrlVerifier::with_loopback(receiver);
    let refresh = verifier.spawn_refresh(RevocationNetwork::default());
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.requests(CRL) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refresh task must prefetch the CRL");
    // The prefetch stores the CRL after the response arrives.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let address = peer.serve().await;

    let (result, snapshot) = handshake(&peer, address, &verifier).await;
    refresh.abort();
    result.unwrap();
    assert_eq!(snapshot.diagnostics.revocation_evidence_waits, 0);
    assert_eq!(server.requests(CRL), 1);
}
