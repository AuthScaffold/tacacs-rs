//! Handshake tests for the injected revocation verifier.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslContext, SslMethod};
use openssl::x509::X509;
use tokio::net::TcpListener;

use super::*;
use crate::{
    CertificateTrust, CertificateVerification, ConnectOptions, PreparedEndpoint, PreparedTransport,
    TlsClientConfig,
};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../lde/containers/config/certificates")
            .join(name),
    )
    .unwrap()
}

fn der(name: &str) -> Vec<u8> {
    X509::from_pem(&fixture(name)).unwrap().to_der().unwrap()
}

#[derive(Default)]
struct ScriptedVerifier {
    decisions: Mutex<VecDeque<RevocationDecision>>,
    decides: AtomicUsize,
    obtains: AtomicUsize,
    deadlines: Mutex<Vec<Option<tokio::time::Instant>>>,
}

impl ScriptedVerifier {
    fn new(decisions: impl IntoIterator<Item = RevocationDecision>) -> Arc<Self> {
        Arc::new(Self {
            decisions: Mutex::new(decisions.into_iter().collect()),
            ..Self::default()
        })
    }
}

#[async_trait]
impl RevocationVerifier for ScriptedVerifier {
    fn decide(&self, path: &VerifiedPath) -> RevocationDecision {
        assert_eq!(path.certificates().len(), 2, "the path must run from leaf to anchor");
        assert_eq!(path.peer_identity(), "localhost");
        self.decides.fetch_add(1, Ordering::SeqCst);
        self.decisions
            .lock()
            .unwrap()
            .pop_front()
            .expect("the handshake asked for an unscripted decision")
    }

    async fn obtain(
        &self,
        _path: &VerifiedPath,
        _network: &RevocationNetwork,
        deadline: Option<tokio::time::Instant>,
    ) {
        self.obtains.fetch_add(1, Ordering::SeqCst);
        self.deadlines.lock().unwrap().push(deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn serve_once() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
    context
        .set_certificate(&X509::from_pem(&fixture("server.crt")).unwrap())
        .unwrap();
    context
        .set_private_key(&PKey::private_key_from_pem(&fixture("server.key")).unwrap())
        .unwrap();
    context.set_num_tickets(0).unwrap();
    let context = context.build();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = tokio_openssl::SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
        let _ = Pin::new(&mut stream).accept().await;
    });
    (address, server)
}

async fn connect(
    verifier: Arc<dyn RevocationVerifier>,
    pinned: bool,
) -> (anyhow::Result<()>, crate::StatisticsSnapshot) {
    let (address, server) = serve_once().await;
    let authority = der(if pinned {
        "server.crt"
    } else {
        "ca.crt"
    });
    let authorities: &[&[u8]] = if pinned {
        &[]
    } else {
        &[&authority]
    };
    let end_entities: &[&[u8]] = if pinned {
        &[&authority]
    } else {
        &[]
    };
    let config = TlsClientConfig::prepare(
        "localhost",
        None,
        CertificateTrust::Certificates {
            authorities,
            end_entities,
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
    .with_revocation_verifier(verifier);
    let result = crate::establish::establish_stream(&endpoint)
        .await
        .map(drop);
    server.abort();
    (result, endpoint.counters().snapshot())
}

#[tokio::test]
async fn handshake_pauses_for_evidence_and_resumes_on_the_same_socket() {
    let verifier = ScriptedVerifier::new([
        RevocationDecision::NeedEvidence,
        RevocationDecision::Verified,
    ]);
    let (result, snapshot) = connect(verifier.clone(), false).await;
    result.unwrap();
    assert_eq!(verifier.decides.load(Ordering::SeqCst), 2);
    assert_eq!(verifier.obtains.load(Ordering::SeqCst), 1);
    assert!(
        verifier.deadlines.lock().unwrap()[0].is_some(),
        "the connection timeout must bound the evidence fetch"
    );
    assert_eq!(snapshot.diagnostics.revocation_evidence_waits, 1);
    assert_eq!(snapshot.diagnostics.tls_certificate_errors, 0);
}

#[tokio::test]
async fn missing_evidence_after_resume_rejects_the_server() {
    let verifier = ScriptedVerifier::new([
        RevocationDecision::NeedEvidence,
        RevocationDecision::NeedEvidence,
    ]);
    let (result, snapshot) = connect(verifier.clone(), false).await;
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("revocation evidence is unavailable"), "{error}");
    assert_eq!(verifier.obtains.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot.diagnostics.tls_certificate_errors, 1);
    assert_eq!(snapshot.diagnostics.tls_revoked_certificates, 0);
}

#[tokio::test]
async fn listed_certificate_is_counted_as_revoked() {
    let verifier = ScriptedVerifier::new([RevocationDecision::Reject(
        RevocationRejection::revoked("serial 01 is listed"),
    )]);
    let (result, snapshot) = connect(verifier.clone(), false).await;
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("serial 01 is listed"), "{error}");
    assert_eq!(verifier.obtains.load(Ordering::SeqCst), 0);
    assert_eq!(snapshot.diagnostics.tls_revoked_certificates, 1);
}

#[tokio::test]
async fn policy_acceptance_without_evidence_is_counted() {
    let verifier = ScriptedVerifier::new([RevocationDecision::Accept("warn-only".to_owned())]);
    let (result, snapshot) = connect(verifier, false).await;
    result.unwrap();
    assert_eq!(snapshot.diagnostics.revocation_unverified_accepts, 1);
}

#[tokio::test]
async fn exact_pinned_server_skips_the_verifier() {
    let verifier = ScriptedVerifier::new([]);
    let (result, snapshot) = connect(verifier.clone(), true).await;
    result.unwrap();
    assert_eq!(verifier.decides.load(Ordering::SeqCst), 0);
    assert_eq!(snapshot.diagnostics.revocation_pinned_skips, 1);
}
