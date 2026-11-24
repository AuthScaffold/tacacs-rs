//! Revocation decisions from the evidence in the store.
//!
//! The evaluation does no I/O and verifies no signatures. It uses only CRLs whose
//! signatures were verified with the key of the issuer certificate in the path.
//! It is cheap enough to run inside the OpenSSL verify callback.

use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use openssl::x509::{CrlStatus, X509, X509Ref};
use tacacsrs_networking::{
    DistributionPointUrl, RevocationDecision, RevocationEnforcement, RevocationRejection,
    RevocationSettings,
};

use crate::certificate::CertificateInfo;
use crate::crl::{Crl, hex};
use crate::store::{Backoff, Store};

/// Accepted clock difference for a CRL `thisUpdate` in the future.
const CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Time after which a decision without fresh evidence is evaluated again.
const RECHECK: Duration = Duration::from_secs(30);

/// Time for which a revoked decision stays cached.
const REVOKED_CACHE: Duration = Duration::from_secs(600);

/// Time after a successful fetch during which the URL is not fetched again.
///
/// A CRL that does not match the issuer key in a path does not improve when
/// it is fetched again a moment later.
const RECENT_FETCH: Duration = Duration::from_secs(10);

/// Time for which a path without revocable certificates stays cached.
const TRIVIAL_CACHE: Duration = Duration::from_secs(3600);

/// The kind of a final decision, for counters and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecisionKind {
    Verified,
    GraceAccept,
    WarnAccept,
    Revoked,
    Unverified,
}

/// A decision that does not need more evidence.
#[derive(Debug, Clone)]
pub(crate) struct FinalDecision {
    pub(crate) decision: RevocationDecision,
    pub(crate) kind: DecisionKind,
    pub(crate) valid_until: SystemTime,
}

/// Evidence that could change the decision.
#[derive(Debug, Default)]
pub(crate) struct Need {
    /// Groups of mirror URLs. One successful fetch per group is enough.
    pub(crate) fetch: Vec<Vec<DistributionPointUrl>>,
    /// An unverified candidate CRL can be checked against the issuer key.
    pub(crate) prepare: bool,
}

impl Need {
    pub(crate) fn is_empty(&self) -> bool {
        self.fetch.is_empty() && !self.prepare
    }
}

/// The result of one evaluation.
#[derive(Debug)]
pub(crate) enum Outcome {
    Final(FinalDecision),
    Need(Need),
}

/// The inputs of one evaluation.
pub(crate) struct Evaluation<'a> {
    pub(crate) settings: &'a RevocationSettings,
    pub(crate) store: &'a Store,
    pub(crate) backoff: &'a Backoff,
    pub(crate) now: SystemTime,
    pub(crate) instant: Instant,
    /// Converts missing evidence to a policy decision instead of `Need`.
    pub(crate) final_only: bool,
}

enum Status {
    Good { until: SystemTime },
    Stale { until: SystemTime, reason: String },
    Missing { reason: String },
    Revoked { reason: String },
}

#[derive(Default)]
struct Scan {
    need: Need,
    retry: Option<Instant>,
    skipped: usize,
}

/// Returns the allowed HTTP URLs in `uris`, in order and without duplicates.
pub(crate) fn allowed_urls(
    uris: &[String],
    settings: &RevocationSettings,
) -> Vec<DistributionPointUrl> {
    let mut urls: Vec<DistributionPointUrl> = Vec::new();
    for uri in uris {
        if !uri
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
        {
            log::debug!("Ignored a non-HTTP CRL distribution point");
            continue;
        }
        match DistributionPointUrl::parse(uri) {
            Ok(url) if settings.allows(&url) => {
                if !urls.contains(&url) {
                    urls.push(url);
                }
            }
            Ok(url) => log::debug!("CRL distribution point {url} matches no allowed pattern"),
            Err(error) => log::debug!("Ignored an invalid CRL distribution point: {error:#}"),
        }
    }
    urls
}

/// Describes a certificate for logs and rejection reasons.
pub(crate) fn describe(depth: usize, certificate: &X509Ref) -> String {
    let serial = certificate
        .serial_number()
        .to_bn()
        .map(|serial| hex(&serial.to_vec()))
        .unwrap_or_default();
    format!("certificate at depth {depth} (serial {serial})")
}

impl Evaluation<'_> {
    /// Evaluates `path` and returns the outcome and the number of URLs skipped because of back-off.
    pub(crate) fn evaluate(&self, path: &[X509]) -> (Outcome, usize) {
        let mut scan = Scan::default();
        let mut statuses = Vec::with_capacity(path.len());
        for (depth, pair) in path.windows(2).enumerate() {
            let status = self.certificate_status(depth, &pair[0], &pair[1], &mut scan);
            if let Status::Revoked { reason } = status {
                let decision = FinalDecision {
                    decision: RevocationDecision::Reject(RevocationRejection::revoked(reason)),
                    kind: DecisionKind::Revoked,
                    valid_until: self.now + REVOKED_CACHE,
                };
                return (Outcome::Final(decision), scan.skipped);
            }
            statuses.push(status);
        }
        if !self.final_only && !scan.need.is_empty() {
            return (Outcome::Need(scan.need), scan.skipped);
        }
        (Outcome::Final(self.combine(statuses, scan.retry)), scan.skipped)
    }

    fn combine(&self, statuses: Vec<Status>, retry: Option<Instant>) -> FinalDecision {
        let mut fresh_until = self.now + TRIVIAL_CACHE;
        let mut grace_until: Option<SystemTime> = None;
        let mut inside_grace = true;
        let mut problems = Vec::new();
        for status in statuses {
            match status {
                Status::Good { until } => fresh_until = fresh_until.min(until),
                Status::Stale { until, reason } => {
                    let end = until
                        .checked_add(self.settings.soft_fail_grace)
                        .unwrap_or(until);
                    inside_grace &= self.now < end;
                    grace_until = Some(grace_until.map_or(end, |current| current.min(end)));
                    problems.push(reason);
                }
                Status::Missing { reason } => {
                    inside_grace = false;
                    problems.push(reason);
                }
                Status::Revoked { .. } => {}
            }
        }
        if problems.is_empty() {
            return FinalDecision {
                decision: RevocationDecision::Verified,
                kind: DecisionKind::Verified,
                valid_until: fresh_until,
            };
        }
        let mut recheck = self.now + RECHECK;
        if let Some(retry) = retry {
            let wait = retry.saturating_duration_since(self.instant);
            recheck = recheck.min(self.now + wait.max(Duration::from_secs(1)));
        }
        let problems = problems.join("; ");
        let (decision, kind, valid_until) = match self.settings.enforcement {
            RevocationEnforcement::Disabled => {
                (RevocationDecision::Verified, DecisionKind::Verified, recheck)
            }
            RevocationEnforcement::SoftFail if inside_grace => (
                RevocationDecision::Accept(format!(
                    "soft-fail accepted validated CRLs inside the grace period: {problems}"
                )),
                DecisionKind::GraceAccept,
                grace_until.map_or(recheck, |end| end.min(recheck).min(fresh_until)),
            ),
            RevocationEnforcement::HardFail | RevocationEnforcement::SoftFail => (
                RevocationDecision::Reject(RevocationRejection::unverified(problems)),
                DecisionKind::Unverified,
                recheck,
            ),
            RevocationEnforcement::WarnOnly => (
                RevocationDecision::Accept(format!(
                    "warn-only accepted the server without revocation evidence: {problems}"
                )),
                DecisionKind::WarnAccept,
                recheck,
            ),
        };
        FinalDecision {
            decision,
            kind,
            valid_until,
        }
    }

    fn certificate_status(
        &self,
        depth: usize,
        certificate: &X509,
        issuer: &X509,
        scan: &mut Scan,
    ) -> Status {
        let name = describe(depth, certificate);
        let info = match CertificateInfo::read(certificate) {
            Ok(info) => info,
            Err(error) => {
                return Status::Missing {
                    reason: format!("{name} has unreadable revocation extensions: {error:#}"),
                };
            }
        };
        let key_der = match issuer.public_key().and_then(|key| key.public_key_to_der()) {
            Ok(key) => key,
            Err(error) => {
                return Status::Missing {
                    reason: format!("the issuer key of {name} is unreadable: {error}"),
                };
            }
        };
        let points = allowed_urls(&info.distribution_points, self.settings);
        if points.is_empty() {
            return Status::Missing {
                reason: format!("{name} has no allowed HTTP CRL distribution point"),
            };
        }
        let issuer_matches = |crl: &Crl| {
            crl.crl
                .issuer_name()
                .try_cmp(certificate.issuer_name())
                .is_ok_and(Ordering::is_eq)
        };
        let Some(base) = self.select(&points, &key_der, |crl| {
            !crl.is_delta() && issuer_matches(crl) && crl.scope.applies_to(&info)
        }) else {
            self.want(&points, &key_der, scan);
            return Status::Missing {
                reason: format!("no validated CRL covers {name}"),
            };
        };
        let mut delta_uris = info.freshest.clone();
        delta_uris.extend(base.freshest.iter().cloned());
        let requires_delta = !delta_uris.is_empty();
        let delta_points = allowed_urls(&delta_uris, self.settings);
        let delta = if requires_delta {
            self.select(&delta_points, &key_der, |crl| {
                crl.is_delta_for(&base) && crl.scope.applies_to(&info)
            })
        } else {
            None
        };
        let delta_window = delta.as_ref().map(|delta| self.window(delta, &name));
        match (
            delta
                .as_ref()
                .map(|delta| delta.crl.get_by_cert(certificate)),
            &delta_window,
        ) {
            (Some(CrlStatus::Revoked(_)), Some(Ok(_))) => {
                return Status::Revoked {
                    reason: format!("a CRL lists {name} as revoked"),
                };
            }
            (Some(CrlStatus::RemoveFromCrl(_)), Some(Ok(_))) => {}
            _ => match base.crl.get_by_cert(certificate) {
                CrlStatus::Revoked(_) if base.this_update <= self.now + CLOCK_SKEW => {
                    if requires_delta && !self.final_only && !matches!(delta_window, Some(Ok(_))) {
                        let before_fetch = scan.need.fetch.len();
                        let before_prepare = scan.need.prepare;
                        self.want(&delta_points, &key_der, scan);
                        if scan.need.fetch.len() > before_fetch
                            || (!before_prepare && scan.need.prepare)
                        {
                            return Status::Missing {
                                reason: format!("the delta CRL for {name} is missing"),
                            };
                        }
                    }
                    return Status::Revoked {
                        reason: format!("a CRL lists {name} as revoked"),
                    };
                }
                CrlStatus::Revoked(_) | CrlStatus::NotRevoked => {}
                CrlStatus::RemoveFromCrl(_) => {
                    return Status::Missing {
                        reason: format!("the base CRL for {name} contains removeFromCRL"),
                    };
                }
            },
        }
        let mut until = match self.window(&base, &name) {
            Ok(until) => until,
            Err(reason) => {
                self.want(&points, &key_der, scan);
                return Status::Missing { reason };
            }
        };
        if requires_delta {
            let Some(delta_window) = delta_window else {
                self.want(&delta_points, &key_der, scan);
                return Status::Missing {
                    reason: format!("the delta CRL for {name} is missing"),
                };
            };
            match delta_window {
                Ok(delta_until) => until = until.min(delta_until),
                Err(reason) => {
                    self.want(&delta_points, &key_der, scan);
                    return Status::Missing { reason };
                }
            }
        }
        if self.now < until {
            return Status::Good { until };
        }
        self.want(&points, &key_der, scan);
        if requires_delta {
            self.want(&delta_points, &key_der, scan);
        }
        Status::Stale {
            until,
            reason: format!("the CRL for {name} is past its nextUpdate"),
        }
    }

    fn window(&self, crl: &Crl, name: &str) -> Result<SystemTime, String> {
        if crl.this_update > self.now + CLOCK_SKEW {
            return Err(format!("the CRL for {name} is not valid yet"));
        }
        crl.next_update
            .ok_or_else(|| format!("the CRL for {name} has no nextUpdate"))
    }

    fn select(
        &self,
        urls: &[DistributionPointUrl],
        key_der: &[u8],
        accept: impl Fn(&Crl) -> bool,
    ) -> Option<Arc<Crl>> {
        urls.iter()
            .filter_map(|url| self.store.verified(url.as_str(), key_der))
            .filter(|crl| accept(crl))
            .max_by(|left, right| left.recency(right))
            .cloned()
    }

    fn want(&self, urls: &[DistributionPointUrl], key_der: &[u8], scan: &mut Scan) {
        if urls
            .iter()
            .any(|url| self.store.candidate(url.as_str(), key_der).is_some())
        {
            scan.need.prepare = true;
            return;
        }
        let mut fetchable = Vec::new();
        for url in urls {
            match self.backoff.blocked_until(url.as_str(), self.instant) {
                Some(until) => {
                    scan.skipped += 1;
                    scan.retry = Some(scan.retry.map_or(until, |current| current.min(until)));
                }
                None => {
                    let recent = self
                        .store
                        .entry(url.as_str())
                        .and_then(|entry| entry.last_stored)
                        .is_some_and(|stored| {
                            self.instant.saturating_duration_since(stored) < RECENT_FETCH
                        });
                    if !recent {
                        fetchable.push(url.clone());
                    }
                }
            }
        }
        if !fetchable.is_empty() && !scan.need.fetch.iter().any(|group| group == &fetchable) {
            scan.need.fetch.push(fetchable);
        }
    }
}
