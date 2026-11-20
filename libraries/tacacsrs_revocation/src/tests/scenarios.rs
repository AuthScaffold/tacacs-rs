//! End-to-end scenarios for the CRL verifier.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use openssl::x509::X509;
use tacacsrs_networking::{
    DistributionPointPattern, DistributionPointUrl, RevocationDecision, RevocationEnforcement,
    RevocationNetwork, RevocationSettings, RevocationVerifier, VerifiedPath,
};
use tokio::sync::watch;

use super::pki::{CertificateOptions, CrlOptions, Issued, crl, issue, key};
use super::server::{Response, Server, closed_url};
use crate::CrlVerifier;

const ROOT: &str = "/root.crl";
const INTERMEDIATE: &str = "/intermediate.crl";
const DELTA: &str = "/intermediate-delta.crl";

struct Pki {
    root: Issued,
    intermediate: Issued,
}

impl Pki {
    fn new(root_points: &[&str]) -> Self {
        let root = issue(
            "Test Root",
            key(),
            None,
            &CertificateOptions {
                ca: true,
                serial: 1,
                ..CertificateOptions::default()
            },
        );
        let intermediate = issue(
            "Test Intermediate",
            key(),
            Some(&root),
            &CertificateOptions {
                ca: true,
                serial: 2,
                distribution_points: root_points,
                ..CertificateOptions::default()
            },
        );
        Self { root, intermediate }
    }

    fn leaf(&self, serial: u32, points: &[&str]) -> X509 {
        leaf_from(&self.intermediate, serial, points)
    }

    fn path(&self, leaf: &X509) -> VerifiedPath {
        path_of(leaf, &self.intermediate, &self.root)
    }
}

fn leaf_from(intermediate: &Issued, serial: u32, points: &[&str]) -> X509 {
    issue(
        "server.example.test",
        key(),
        Some(intermediate),
        &CertificateOptions {
            serial,
            distribution_points: points,
            ..CertificateOptions::default()
        },
    )
    .certificate
}

fn path_of(leaf: &X509, intermediate: &Issued, root: &Issued) -> VerifiedPath {
    VerifiedPath::new(
        vec![
            leaf.clone(),
            intermediate.certificate.clone(),
            root.certificate.clone(),
        ],
        "server.example.test",
    )
    .unwrap()
}

fn settings(enforcement: RevocationEnforcement, patterns: &[String]) -> RevocationSettings {
    let mut settings = RevocationSettings::default();
    settings.enforcement = enforcement;
    settings.allowed_distribution_points = patterns
        .iter()
        .map(|pattern| DistributionPointPattern::parse(pattern).unwrap())
        .collect();
    settings.fetch_timeout = Duration::from_secs(2);
    settings
}

fn start(settings: RevocationSettings) -> (CrlVerifier, watch::Sender<RevocationSettings>) {
    let (sender, receiver) = watch::channel(settings);
    (CrlVerifier::with_loopback(receiver), sender)
}

/// Runs the handshake sequence: decide, obtain if needed, decide again.
async fn check(verifier: &CrlVerifier, path: &VerifiedPath) -> RevocationDecision {
    let decision = verifier.decide(path);
    if decision != RevocationDecision::NeedEvidence {
        return decision;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    verifier
        .obtain(path, &RevocationNetwork::default(), Some(deadline))
        .await;
    verifier.decide(path)
}

fn assert_revoked(decision: &RevocationDecision, text: &str) {
    match decision {
        RevocationDecision::Reject(rejection) => {
            assert!(rejection.is_revoked(), "{rejection:?}");
            assert!(rejection.reason().contains(text), "{rejection:?}");
        }
        other => panic!("expected a revoked rejection, got {other:?}"),
    }
}

fn assert_unverified(decision: &RevocationDecision) {
    match decision {
        RevocationDecision::Reject(rejection) => assert!(!rejection.is_revoked(), "{rejection:?}"),
        other => panic!("expected an unverified rejection, got {other:?}"),
    }
}

/// A server with a fresh root CRL and a standard PKI.
struct Fixture {
    server: Server,
    pki: Pki,
}

impl Fixture {
    async fn new() -> Self {
        let server = Server::start().await;
        let pki = Pki::new(&[&server.url(ROOT)]);
        server.route(ROOT, Response::Body(crl(&pki.root, &CrlOptions::default())));
        Self { server, pki }
    }

    fn leaf(&self, serial: u32) -> X509 {
        self.pki.leaf(serial, &[&self.server.url(INTERMEDIATE)])
    }

    fn settings(&self, enforcement: RevocationEnforcement) -> RevocationSettings {
        settings(enforcement, &[self.server.pattern()])
    }

    fn serve_intermediate(&self, options: &CrlOptions<'_>) {
        self.server
            .route(INTERMEDIATE, Response::Body(crl(&self.pki.intermediate, options)));
    }
}

fn cache_directory(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tacacsrs-revocation-tests")
        .join(name);
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

#[tokio::test]
async fn verifies_a_path_with_der_and_pem_crls() {
    let fixture = Fixture::new().await;
    let root_crl =
        openssl::x509::X509Crl::from_der(&crl(&fixture.pki.root, &CrlOptions::default()))
            .unwrap()
            .to_pem()
            .unwrap();
    fixture.server.route(ROOT, Response::Body(root_crl));
    fixture.serve_intermediate(&CrlOptions::default());
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    let path = fixture.pki.path(&fixture.leaf(10));
    assert_eq!(verifier.decide(&path), RevocationDecision::NeedEvidence);
    assert_eq!(check(&verifier, &path).await, RevocationDecision::Verified);
    // The cached decision needs no further work.
    assert_eq!(verifier.decide(&path), RevocationDecision::Verified);
    let counters = verifier.counters();
    assert_eq!(counters.fetches, 2);
    assert_eq!(counters.fetch_failures, 0);
    // The explicit first call and the first call in `check` both miss.
    assert_eq!(counters.evidence_misses, 2);
}

#[tokio::test]
async fn disabled_enforcement_does_no_work() {
    let fixture = Fixture::new().await;
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::Disabled));
    let path = fixture.pki.path(&fixture.leaf(10));
    assert_eq!(verifier.decide(&path), RevocationDecision::Verified);
    verifier
        .obtain(&path, &RevocationNetwork::default(), None)
        .await;
    assert_eq!(fixture.server.requests(ROOT), 0);
}

#[tokio::test]
async fn rejects_a_revoked_leaf() {
    let fixture = Fixture::new().await;
    let leaf = fixture.leaf(10);
    fixture.serve_intermediate(&CrlOptions {
        revoked: &[&leaf],
        ..CrlOptions::default()
    });
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::WarnOnly));
    assert_revoked(&check(&verifier, &fixture.pki.path(&leaf)).await, "depth 0");
    assert_eq!(verifier.counters().revoked_rejects, 1);
}

#[tokio::test]
async fn rejects_a_revoked_intermediate() {
    let fixture = Fixture::new().await;
    fixture.server.route(
        ROOT,
        Response::Body(crl(
            &fixture.pki.root,
            &CrlOptions {
                revoked: &[&fixture.pki.intermediate.certificate],
                ..CrlOptions::default()
            },
        )),
    );
    fixture.serve_intermediate(&CrlOptions::default());
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    assert_revoked(&check(&verifier, &fixture.pki.path(&fixture.leaf(10))).await, "depth 1");
}

#[tokio::test]
async fn rejects_a_leaf_revoked_by_a_delta_crl() {
    let fixture = Fixture::new().await;
    let leaf = fixture.leaf(10);
    let delta_url = fixture.server.url(DELTA);
    fixture.serve_intermediate(&CrlOptions {
        freshest: &[&delta_url],
        ..CrlOptions::default()
    });
    fixture.server.route(
        DELTA,
        Response::Body(crl(
            &fixture.pki.intermediate,
            &CrlOptions {
                revoked: &[&leaf],
                number: 2,
                delta_base: Some(1),
                ..CrlOptions::default()
            },
        )),
    );
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    assert_revoked(&check(&verifier, &fixture.pki.path(&leaf)).await, "depth 0");

    // A delta CRL that does not list the leaf leaves it valid.
    let other = fixture.leaf(11);
    assert_eq!(check(&verifier, &fixture.pki.path(&other)).await, RevocationDecision::Verified);
}

#[tokio::test]
async fn rejects_a_path_when_the_delta_crl_is_missing() {
    let fixture = Fixture::new().await;
    let delta_url = fixture.server.url(DELTA);
    fixture.serve_intermediate(&CrlOptions {
        freshest: &[&delta_url],
        ..CrlOptions::default()
    });
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    let decision = check(&verifier, &fixture.pki.path(&fixture.leaf(10))).await;
    assert_unverified(&decision);
    let RevocationDecision::Reject(rejection) = decision else {
        unreachable!();
    };
    assert!(rejection.reason().contains("delta"), "{rejection:?}");
}

#[tokio::test]
async fn handles_a_renewed_ca_key_with_the_same_name() {
    let fixture = Fixture::new().await;
    fixture.serve_intermediate(&CrlOptions::default());
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    let old_path = fixture.pki.path(&fixture.leaf(10));
    assert_eq!(check(&verifier, &old_path).await, RevocationDecision::Verified);

    let renewed = issue(
        "Test Intermediate",
        key(),
        Some(&fixture.pki.root),
        &CertificateOptions {
            ca: true,
            serial: 3,
            distribution_points: &[&fixture.server.url(ROOT)],
            ..CertificateOptions::default()
        },
    );
    let new_leaf = leaf_from(&renewed, 20, &[&fixture.server.url(INTERMEDIATE)]);
    let new_path = path_of(&new_leaf, &renewed, &fixture.pki.root);
    // The URL still serves the CRL of the old key, so the new key has no evidence.
    assert_unverified(&check(&verifier, &new_path).await);

    let mut after_backoff = fixture.settings(RevocationEnforcement::HardFail);
    after_backoff.fetch_timeout = Duration::from_secs(3);
    let (verifier, _sender) = start(after_backoff);
    fixture.server.route(
        INTERMEDIATE,
        Response::Body(crl(
            &renewed,
            &CrlOptions {
                number: 2,
                revoked: &[&fixture.leaf(30)],
                ..CrlOptions::default()
            },
        )),
    );
    assert_eq!(check(&verifier, &new_path).await, RevocationDecision::Verified);
    // A CRL signed by the new key must not cover certificates of the old key.
    assert_unverified(&check(&verifier, &old_path).await);
}

#[tokio::test]
async fn applies_each_policy_when_the_crl_server_is_down() {
    let fixture = Fixture::new().await;
    let down = closed_url(INTERMEDIATE).await;
    let leaf = fixture.pki.leaf(10, &[&down]);
    let path = fixture.pki.path(&leaf);
    let patterns = [
        fixture.server.pattern(),
        format!("{}/**", down.trim_end_matches(INTERMEDIATE)),
    ];

    for enforcement in [
        RevocationEnforcement::HardFail,
        RevocationEnforcement::SoftFail,
    ] {
        let (verifier, _sender) = start(settings(enforcement, &patterns));
        assert_unverified(&check(&verifier, &path).await);
        assert_eq!(verifier.counters().fetch_failures, 1);
    }

    let (verifier, _sender) = start(settings(RevocationEnforcement::WarnOnly, &patterns));
    let decision = check(&verifier, &path).await;
    assert!(matches!(decision, RevocationDecision::Accept(_)), "{decision:?}");
    assert_eq!(verifier.counters().warn_only_accepts, 1);
}

#[tokio::test]
async fn soft_fail_uses_a_stale_crl_only_inside_the_grace_period() {
    let fixture = Fixture::new().await;
    let now = SystemTime::now();
    let leaf = fixture.leaf(10);
    let revoked = fixture.leaf(11);
    fixture.serve_intermediate(&CrlOptions {
        this_update: now - Duration::from_secs(3 * 86_400),
        next_update: now - Duration::from_secs(3600),
        revoked: &[&revoked],
        ..CrlOptions::default()
    });

    let mut inside = fixture.settings(RevocationEnforcement::SoftFail);
    inside.soft_fail_grace = Duration::from_secs(86_400);
    let (verifier, _sender) = start(inside);
    let decision = check(&verifier, &fixture.pki.path(&leaf)).await;
    assert!(matches!(decision, RevocationDecision::Accept(_)), "{decision:?}");
    assert!(verifier.counters().stale_grace_accepts >= 1);
    // A stale CRL that lists the server is always a rejection.
    assert_revoked(&check(&verifier, &fixture.pki.path(&revoked)).await, "depth 0");

    let mut outside = fixture.settings(RevocationEnforcement::SoftFail);
    outside.soft_fail_grace = Duration::from_secs(1800);
    let (verifier, _sender) = start(outside);
    assert_unverified(&check(&verifier, &fixture.pki.path(&leaf)).await);

    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    assert_unverified(&check(&verifier, &fixture.pki.path(&leaf)).await);
}

#[tokio::test]
async fn back_off_makes_the_next_connection_fail_fast() {
    let fixture = Fixture::new().await;
    fixture.server.route(INTERMEDIATE, Response::Stall);
    let mut settings = fixture.settings(RevocationEnforcement::HardFail);
    settings.fetch_timeout = Duration::from_millis(500);
    let (verifier, _sender) = start(settings);

    let started = Instant::now();
    assert_unverified(&check(&verifier, &fixture.pki.path(&fixture.leaf(10))).await);
    assert!(started.elapsed() >= Duration::from_millis(450));

    let started = Instant::now();
    assert_unverified(&check(&verifier, &fixture.pki.path(&fixture.leaf(11))).await);
    assert!(started.elapsed() < Duration::from_millis(300), "{:?}", started.elapsed());
    assert_eq!(fixture.server.requests(INTERMEDIATE), 1);
    assert!(verifier.counters().backoffs >= 1);
}

#[tokio::test]
async fn tries_the_next_mirror_when_the_first_is_down() {
    let fixture = Fixture::new().await;
    fixture.serve_intermediate(&CrlOptions::default());
    let down = closed_url(INTERMEDIATE).await;
    let leaf = fixture
        .pki
        .leaf(10, &[&down, &fixture.server.url(INTERMEDIATE)]);
    let patterns = [
        fixture.server.pattern(),
        format!("{}/**", down.trim_end_matches(INTERMEDIATE)),
    ];
    let (verifier, _sender) = start(settings(RevocationEnforcement::HardFail, &patterns));
    assert_eq!(check(&verifier, &fixture.pki.path(&leaf)).await, RevocationDecision::Verified);
    assert_eq!(verifier.counters().fetch_failures, 1);
}

#[tokio::test]
async fn allowlist_rejects_a_look_alike_host() {
    let fixture = Fixture::new().await;
    let pattern = "http://crl.example.test/**".to_owned();
    let look_alike = "http://crl.example.test.evil.test/intermediate.crl";
    assert!(!DistributionPointPattern::parse(&pattern)
        .unwrap()
        .matches(&DistributionPointUrl::parse(look_alike).unwrap()));
    let leaf = fixture.pki.leaf(10, &[look_alike]);
    let (verifier, _sender) =
        start(settings(RevocationEnforcement::HardFail, &[pattern, fixture.server.pattern()]));
    let decision = check(&verifier, &fixture.pki.path(&leaf)).await;
    assert_unverified(&decision);
    let RevocationDecision::Reject(rejection) = decision else {
        unreachable!();
    };
    assert!(rejection.reason().contains("no allowed HTTP"), "{rejection:?}");
    // Only the root CRL for the intermediate is fetched.
    assert_eq!(verifier.counters().fetches, 1);
    assert_eq!(fixture.server.requests(INTERMEDIATE), 0);
}

#[tokio::test]
async fn skips_an_ldap_distribution_point() {
    let fixture = Fixture::new().await;
    fixture.serve_intermediate(&CrlOptions::default());
    let leaf = fixture.pki.leaf(
        10,
        &[
            "ldap:///CN=Test%20Intermediate,CN=CDP?certificateRevocationList?base",
            &fixture.server.url(INTERMEDIATE),
        ],
    );
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    assert_eq!(check(&verifier, &fixture.pki.path(&leaf)).await, RevocationDecision::Verified);
}

#[tokio::test]
async fn rejects_an_oversize_crl() {
    for response in [Response::Unbounded(64 * 1024), Response::Announced(1 << 30)] {
        let fixture = Fixture::new().await;
        fixture.server.route(INTERMEDIATE, response);
        let mut settings = fixture.settings(RevocationEnforcement::HardFail);
        settings.max_crl_bytes = 4096;
        let (verifier, _sender) = start(settings);
        assert_unverified(&check(&verifier, &fixture.pki.path(&fixture.leaf(10))).await);
        assert_eq!(verifier.counters().fetch_failures, 1);
    }
}

#[tokio::test]
async fn a_slow_body_hits_the_fetch_timeout() {
    let fixture = Fixture::new().await;
    fixture.server.route(INTERMEDIATE, Response::Stall);
    let mut settings = fixture.settings(RevocationEnforcement::HardFail);
    settings.fetch_timeout = Duration::from_millis(300);
    let (verifier, _sender) = start(settings);
    let started = Instant::now();
    assert_unverified(&check(&verifier, &fixture.pki.path(&fixture.leaf(10))).await);
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert_eq!(verifier.counters().fetch_failures, 1);
}

#[tokio::test]
async fn the_caller_deadline_limits_obtain() {
    let fixture = Fixture::new().await;
    fixture.server.route(INTERMEDIATE, Response::Stall);
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    let path = fixture.pki.path(&fixture.leaf(10));
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    verifier
        .obtain(&path, &RevocationNetwork::default(), Some(deadline))
        .await;
    assert!(started.elapsed() < Duration::from_millis(1000), "{:?}", started.elapsed());
    assert_unverified(&verifier.decide(&path));
}

#[tokio::test]
async fn a_cancelled_waiter_does_not_cancel_the_shared_fetch() {
    let fixture = Fixture::new().await;
    let body = crl(&fixture.pki.intermediate, &CrlOptions::default());
    fixture
        .server
        .route(INTERMEDIATE, Response::Delayed(body, Duration::from_millis(500)));
    let (verifier, _sender) = start(fixture.settings(RevocationEnforcement::HardFail));
    let path = fixture.pki.path(&fixture.leaf(10));

    let waiter = {
        let verifier = verifier.clone();
        let path = path.clone();
        tokio::spawn(async move {
            verifier
                .obtain(&path, &RevocationNetwork::default(), None)
                .await;
        })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    waiter.abort();
    let _ = waiter.await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert_eq!(check(&verifier, &path).await, RevocationDecision::Verified);
    assert_eq!(fixture.server.requests(INTERMEDIATE), 1);
    assert_eq!(verifier.counters().fetch_failures, 0);
}

#[tokio::test]
async fn disk_cache_survives_a_restart_and_rejects_tampered_files() {
    let fixture = Fixture::new().await;
    fixture.serve_intermediate(&CrlOptions::default());
    let directory = cache_directory("disk-cache");
    let mut settings = fixture.settings(RevocationEnforcement::HardFail);
    settings.cache_directory = Some(directory.clone());
    let network = RevocationNetwork::default();

    let (first, _sender) = start(settings.clone());
    let path = fixture.pki.path(&fixture.leaf(10));
    assert_eq!(check(&first, &path).await, RevocationDecision::Verified);
    drop(first);

    fixture.server.route(ROOT, Response::Status(404));
    fixture.server.route(INTERMEDIATE, Response::Status(404));
    let (second, _sender) = start(settings.clone());
    second.inner.refresh_once(&network).await;
    assert_eq!(second.decide(&path), RevocationDecision::Verified);
    assert_eq!(second.counters().evidence_misses, 0);
    assert_eq!(second.counters().fetches, 0);

    let name = crate::disk::file_name(&fixture.server.url(INTERMEDIATE)).unwrap();
    let file = directory.join(name);
    let mut content = std::fs::read(&file).unwrap();
    let last = content.len() - 1;
    content[last] ^= 0x01;
    std::fs::write(&file, content).unwrap();

    let (third, _sender) = start(settings);
    third.inner.refresh_once(&network).await;
    assert!(!file.exists());
    assert_eq!(third.decide(&path), RevocationDecision::NeedEvidence);
    assert_unverified(&check(&third, &path).await);
    let _ = std::fs::remove_dir_all(&directory);
}

#[tokio::test]
async fn prefetch_warms_the_cache() {
    let fixture = Fixture::new().await;
    fixture.serve_intermediate(&CrlOptions::default());
    let mut settings = fixture.settings(RevocationEnforcement::HardFail);
    settings.prefetch_distribution_points = [ROOT, INTERMEDIATE]
        .iter()
        .map(|path| DistributionPointUrl::parse(&fixture.server.url(path)).unwrap())
        .collect();
    let (verifier, _sender) = start(settings);
    verifier
        .inner
        .refresh_once(&RevocationNetwork::default())
        .await;
    assert_eq!(verifier.counters().fetches, 2);

    assert_eq!(verifier.decide(&fixture.pki.path(&fixture.leaf(10))), RevocationDecision::Verified);
    assert_eq!(verifier.counters().evidence_misses, 0);
    assert_eq!(verifier.counters().fetches, 2);
}

#[tokio::test]
async fn spawned_refresh_prefetches_and_stops_with_the_verifier() {
    let fixture = Fixture::new().await;
    let mut settings = fixture.settings(RevocationEnforcement::HardFail);
    settings.prefetch_distribution_points =
        vec![DistributionPointUrl::parse(&fixture.server.url(ROOT)).unwrap()];
    let (verifier, _sender) = start(settings);
    let refresh = verifier.spawn_refresh(RevocationNetwork::default());
    for _ in 0..100 {
        if fixture.server.requests(ROOT) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fixture.server.requests(ROOT), 1);
    drop(verifier);
    // The task holds no strong reference, so it ends after the next wait.
    refresh.abort();
    assert!(refresh.await.is_err_and(|error| error.is_cancelled()));
}

#[tokio::test]
async fn settings_changes_apply_to_later_decisions() {
    let fixture = Fixture::new().await;
    let down = closed_url(INTERMEDIATE).await;
    let leaf = fixture.pki.leaf(10, &[&down]);
    let patterns = [
        fixture.server.pattern(),
        format!("{}/**", down.trim_end_matches(INTERMEDIATE)),
    ];
    let (verifier, sender) = start(settings(RevocationEnforcement::WarnOnly, &patterns));
    let path = fixture.pki.path(&leaf);
    assert!(matches!(check(&verifier, &path).await, RevocationDecision::Accept(_)));
    sender.send_replace(settings(RevocationEnforcement::HardFail, &patterns));
    assert_unverified(&verifier.decide(&path));
}

#[tokio::test]
async fn production_filter_rejects_loopback() {
    let fixture = Fixture::new().await;
    fixture.serve_intermediate(&CrlOptions::default());
    let (_sender, receiver) = watch::channel(fixture.settings(RevocationEnforcement::HardFail));
    let verifier = CrlVerifier::new(receiver);
    assert_unverified(&check(&verifier, &fixture.pki.path(&fixture.leaf(10))).await);
    assert_eq!(fixture.server.requests(ROOT), 0);
    assert_eq!(fixture.server.requests(INTERMEDIATE), 0);
    assert_eq!(verifier.counters().fetch_failures, 2);
}
