use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use tacacsrs_credential_http::{EvidenceFetchLimits, HttpEvidenceResolver, HttpCrlSource};
use tacacsrs_credential_resolution::{
    CredentialKind, CredentialReference, CredentialResolver, FakeCredentialResolver,
    RequestContext, RequestSlot, ResolutionError, ResolutionErrorKind, ResolutionPlan,
    ResolvedCredential, SecretBytes, SymmetricKeyMaterial, CredentialValidity,
};

async fn resolve(
    provider: &HttpEvidenceResolver,
    reference: &str,
) -> Result<ResolvedCredential, ResolutionError> {
    let plan = ResolutionPlan::new([(
        RequestContext::new("server", "revocation"),
        CredentialKind::CertificateRevocationLists,
        CredentialReference::CertificateRevocationLists(reference.to_owned()),
    )])
    .unwrap();
    provider
        .resolve(&plan.requests()[0], &tacacsrs_credential_resolution::WorkScope::unowned())
        .await
}

struct ScopeRetainingFallback(std::sync::Mutex<Option<tacacsrs_credential_resolution::WorkScope>>);

#[async_trait::async_trait]
impl CredentialResolver for ScopeRetainingFallback {
    async fn resolve(
        &self,
        _request: &tacacsrs_credential_resolution::CredentialRequest,
        scope: &tacacsrs_credential_resolution::WorkScope,
    ) -> Result<ResolvedCredential, ResolutionError> {
        *self.0.lock().unwrap() = scope.register();
        Ok(ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
            validity: CredentialValidity::unbounded(),
            key_format: None,
            key: SecretBytes::new(vec![7; 16]),
        }))
    }
}

#[tokio::test]
async fn fallback_retains_the_callers_registered_work_scope() {
    let fallback = Arc::new(ScopeRetainingFallback(std::sync::Mutex::new(None)));
    let provider = HttpEvidenceResolver::new([], EvidenceFetchLimits::default())
        .unwrap()
        .with_fallback(fallback.clone());
    let plan = ResolutionPlan::new([(
        RequestContext::new("server", "epsk"),
        CredentialKind::SymmetricKey,
        CredentialReference::SymmetricKey("opaque".to_owned()),
    )])
    .unwrap();
    let (control, root) = tacacsrs_credential_resolution::WorkScope::new(());
    provider.resolve(&plan.requests()[0], &root).await.unwrap();
    control.seal();
    drop(root);
    assert!(!control.is_quiet());
    fallback.0.lock().unwrap().take();
    assert!(control.is_quiet());
}

async fn reply(body: impl AsRef<[u8]>) -> (String, tokio::task::JoinHandle<()>) {
    let body = body.as_ref().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/private-location", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(stream.read(&mut [0; 4096]).await.unwrap() > 0);
        stream.write_all(&body).await.unwrap();
    });
    (url, task)
}

#[tokio::test]
async fn certificate_discovery_requires_host_authorization_before_fetch() {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509Extension, X509NameBuilder};
    let (url, task) =
        reply(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ncrl").await;
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "discovery-fixture")
        .unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    #[allow(deprecated)]
    let points =
        X509Extension::new(None, None, "crlDistributionPoints", &format!("URI:{url}")).unwrap();
    certificate.append_extension(points).unwrap();
    #[allow(deprecated)]
    let access =
        X509Extension::new(None, None, "authorityInfoAccess", &format!("OCSP;URI:{url}")).unwrap();
    certificate.append_extension(access).unwrap();
    certificate.sign(&key, MessageDigest::sha256()).unwrap();
    let der = certificate.build().to_der().unwrap();
    assert!(tacacsrs_credential_http::HttpOcspSource::from_certificate(
        "online",
        &der,
        &der,
        ["https://not-authorized.test/ocsp"]
    )
    .is_err());
    let online =
        tacacsrs_credential_http::HttpOcspSource::from_certificate("online", &der, &der, [&url])
            .unwrap();
    assert!(!format!("{online:?}").contains(&url));
    let error = HttpCrlSource::from_certificates(
        "private-reference",
        &[&der],
        ["http://example.test/not-authorized"],
    )
    .unwrap_err();
    assert!(!format!("{error:#}").contains(&url));
    assert!(HttpCrlSource::from_certificates("set", &[b"invalid"], [&url]).is_err());
    let mut trailing = der.clone();
    trailing.push(0);
    assert!(HttpCrlSource::from_certificates("set", &[&trailing], [&url]).is_err());
    let source = HttpCrlSource::from_certificates("set", &[&der, &der], [&url]).unwrap();
    let provider = HttpEvidenceResolver::new([source], EvidenceFetchLimits::default()).unwrap();
    let ResolvedCredential::CertificateRevocationLists(material) =
        resolve(&provider, "set").await.unwrap()
    else {
        panic!("wrong material kind");
    };
    assert_eq!(material.lists.len(), 1);
    assert_eq!(material.lists[0].as_bytes(), b"crl");
    task.await.unwrap();
}

#[tokio::test]
async fn retrieves_all_locations_in_order_without_exposing_source_values() {
    let (first, first_task) =
        reply(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none").await;
    let (second, second_task) =
        reply(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo").await;
    let provider = HttpEvidenceResolver::new(
        [HttpCrlSource::new("private-reference", [&first, &second]).unwrap()],
        EvidenceFetchLimits::default(),
    )
    .unwrap();
    let debug = format!("{provider:?}");
    assert!(!debug.contains("private-reference") && !debug.contains("private-location"));
    let ResolvedCredential::CertificateRevocationLists(material) =
        resolve(&provider, "private-reference").await.unwrap()
    else {
        panic!("wrong material kind");
    };
    assert_eq!(
        material
            .lists
            .iter()
            .map(tacacsrs_credential_resolution::PublicBytes::as_bytes)
            .collect::<Vec<_>>(),
        [b"one".as_slice(), b"two".as_slice()]
    );
    assert_eq!(material.validity, CredentialValidity::unbounded());
    first_task.await.unwrap();
    second_task.await.unwrap();
}

#[tokio::test]
async fn rejects_redirects_errors_empty_compressed_and_oversized_bodies() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect = format!("HTTP/1.1 302 Found\r\nLocation: http://{}/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target.local_addr().unwrap());
    let (redirect_source, redirect_task) = reply(redirect.as_bytes()).await;
    let provider = HttpEvidenceResolver::new(
        [HttpCrlSource::new("private-reference", [&redirect_source]).unwrap()],
        EvidenceFetchLimits::default(),
    )
    .unwrap();
    assert_eq!(
        resolve(&provider, "private-reference")
            .await
            .unwrap_err()
            .kind(),
        ResolutionErrorKind::Unavailable
    );
    redirect_task.await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(25), target.accept())
        .await
        .is_err());
    for (response, expected) in [
        (b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(), ResolutionErrorKind::AccessDenied),
        (b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(), ResolutionErrorKind::Unavailable),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabc".as_slice(), ResolutionErrorKind::Unavailable),
        (b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(), ResolutionErrorKind::NotFound),
        (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(), ResolutionErrorKind::AccessDenied),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(), ResolutionErrorKind::InvalidMaterial),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n123456789".as_slice(), ResolutionErrorKind::InvalidMaterial),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n9\r\n123456789\r\n0\r\n\r\n".as_slice(), ResolutionErrorKind::InvalidMaterial),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\nabc".as_slice(), ResolutionErrorKind::InvalidMaterial),
    ] {
        let (url, task) = reply(response).await;
        let provider = HttpEvidenceResolver::new([HttpCrlSource::new("private-reference", [&url]).unwrap()], EvidenceFetchLimits::new(Duration::from_secs(2), 8, 1).unwrap()).unwrap();
        let error = resolve(&provider, "private-reference").await.unwrap_err();
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?} {error}").contains("private-reference"));
        assert!(!format!("{error:?} {error}").contains("private-location"));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn complete_set_limit_is_aggregate_and_partial_results_are_not_returned() {
    for second in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo".as_slice(),
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
    ] {
        let (first, first_task) =
            reply(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none").await;
        let (second, second_task) = reply(second).await;
        let provider = HttpEvidenceResolver::new(
            [HttpCrlSource::new("set", [&first, &second]).unwrap()],
            EvidenceFetchLimits::new(Duration::from_secs(2), 5, 1).unwrap(),
        )
        .unwrap();
        assert!(resolve(&provider, "set").await.is_err());
        first_task.await.unwrap();
        second_task.await.unwrap();
    }
}

#[tokio::test]
async fn cancelling_a_stalled_fetch_closes_io_and_releases_capacity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    let (closed, closure) = tokio::sync::oneshot::channel();
    let url = format!("http://{}/crl", listener.local_addr().unwrap());
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(stream.read(&mut [0; 4096]).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nx")
            .await
            .unwrap();
        let _ = ready.send(());
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        let _ = closed.send(());
    });
    let (good, good_task) =
        reply(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew").await;
    let provider = HttpEvidenceResolver::new(
        [
            HttpCrlSource::new("stalled", [&url]).unwrap(),
            HttpCrlSource::new("good", [&good]).unwrap(),
        ],
        EvidenceFetchLimits::new(Duration::from_secs(10), 64, 1).unwrap(),
    )
    .unwrap();
    let mut pending = Box::pin(resolve(&provider, "stalled"));
    tokio::select! { result = &mut pending => panic!("fetch ended before cancellation: {result:?}"), result = started => result.unwrap() }
    assert_eq!(
        resolve(&provider, "good").await.unwrap_err().kind(),
        ResolutionErrorKind::Unavailable
    );
    drop(pending);
    tokio::time::timeout(Duration::from_secs(1), closure)
        .await
        .unwrap()
        .unwrap();
    resolve(&provider, "good").await.unwrap();
    peer.await.unwrap();
    good_task.await.unwrap();
}

#[tokio::test]
async fn unknown_references_are_not_urls_and_other_kinds_can_use_fallback() {
    let fallback = FakeCredentialResolver::new().with_response(
        RequestSlot::from_index(0),
        ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
            validity: CredentialValidity::unbounded(),
            key_format: None,
            key: SecretBytes::new(b"fallback-key".to_vec()),
        }),
    );
    let provider = HttpEvidenceResolver::new([], EvidenceFetchLimits::default()).unwrap();
    assert_eq!(
        resolve(&provider, "http://127.0.0.1:1/private")
            .await
            .unwrap_err()
            .kind(),
        ResolutionErrorKind::NotFound
    );
    let provider = provider.with_fallback(Arc::new(fallback));
    let plan = ResolutionPlan::new([(
        RequestContext::new("server", "key"),
        CredentialKind::SymmetricKey,
        CredentialReference::SymmetricKey("key".to_owned()),
    )])
    .unwrap();
    assert_eq!(
        provider
            .resolve(&plan.requests()[0], &tacacsrs_credential_resolution::WorkScope::unowned())
            .await
            .unwrap()
            .kind(),
        CredentialKind::SymmetricKey
    );
}

#[tokio::test]
async fn registered_source_failure_never_uses_fallback() {
    use tacacsrs_credential_resolution::{CertificateRevocationListsMaterial, PublicBytes};
    let fallback = Arc::new(FakeCredentialResolver::new().with_response(
        RequestSlot::from_index(0),
        ResolvedCredential::CertificateRevocationLists(CertificateRevocationListsMaterial {
            validity: CredentialValidity::unbounded(),
            lists: vec![PublicBytes::new(b"fallback".to_vec())],
        }),
    ));
    let (url, task) =
        reply(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    let source = HttpCrlSource::new("registered", [&url]).unwrap();
    assert!(HttpEvidenceResolver::new(
        [source.clone(), source.clone()],
        EvidenceFetchLimits::default()
    )
    .is_err());
    let provider = HttpEvidenceResolver::new([source], EvidenceFetchLimits::default())
        .unwrap()
        .with_fallback(fallback);
    assert!(resolve(&provider, "unregistered").await.is_ok());
    assert_eq!(
        resolve(&provider, "registered").await.unwrap_err().kind(),
        ResolutionErrorKind::NotFound
    );
    task.await.unwrap();
}

#[tokio::test]
async fn all_locations_share_one_timeout_and_late_body_is_cancelled() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let urls = [
        format!("http://{}/first", first.local_addr().unwrap()),
        format!("http://{}/second", second.local_addr().unwrap()),
    ];
    let (first_ready, started) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let first_peer = tokio::spawn(async move {
        let (mut stream, _) = first.accept().await.unwrap();
        assert!(stream.read(&mut [0; 4096]).await.unwrap() > 0);
        let _ = first_ready.send(());
        released.await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\na")
            .await
            .unwrap();
    });
    let (second_ready, second_started) = tokio::sync::oneshot::channel();
    let second_peer = tokio::spawn(async move {
        let (mut stream, _) = second.accept().await.unwrap();
        assert!(stream.read(&mut [0; 4096]).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\na")
            .await
            .unwrap();
        let _ = second_ready.send(());
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    });
    let provider = HttpEvidenceResolver::new(
        [HttpCrlSource::new("set", urls).unwrap()],
        EvidenceFetchLimits::new(Duration::from_secs(3), 16, 1).unwrap(),
    )
    .unwrap();
    let beginning = tokio::time::Instant::now();
    let pending = resolve(&provider, "set");
    tokio::pin!(pending);
    tokio::select! { result = &mut pending => panic!("fetch ended before first response: {result:?}"), result = started => result.unwrap() }
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::resume();
    release.send(()).unwrap();
    tokio::select! { result = &mut pending => panic!("fetch ended before second response: {result:?}"), result = second_started => result.unwrap() }
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(1100)).await;
    assert_eq!(pending.await.unwrap_err().kind(), ResolutionErrorKind::Unavailable);
    assert!(
        beginning.elapsed() < Duration::from_secs(4),
        "the second URL must not receive a fresh timeout"
    );
    tokio::time::resume();
    first_peer.await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), second_peer)
        .await
        .unwrap()
        .unwrap();
}
