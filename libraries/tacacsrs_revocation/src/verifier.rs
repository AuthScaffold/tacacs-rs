//! The CRL verifier: decision cache, evidence fetches, and background refresh.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use tacacsrs_networking::{
    DistributionPointUrl, RevocationDecision, RevocationNetwork, RevocationSettings,
    RevocationVerifier, VerifiedPath,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::address::check_address;
use crate::certificate::CertificateInfo;
use crate::crl::{Crl, digest};
use crate::evaluate::{DecisionKind, Evaluation, FinalDecision, Outcome, allowed_urls};
use crate::store::{Backoff, Store};
use crate::{disk, fetch};

/// Largest number of fetch and verification rounds in one `obtain` call.
///
/// A base CRL can name a delta CRL, so one path can need several rounds.
const MAXIMUM_ROUNDS: usize = 4;

/// Time for which a decision from `obtain` survives an evidence change.
///
/// The handshake calls `decide` again right after `obtain`. A concurrent
/// fetch must not turn that call into a second `NeedEvidence`.
const STICKY: Duration = Duration::from_secs(10);

/// Interval of the background refresh.
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Shortest interval between two refreshes of one URL that returned evidence.
const MINIMUM_REFETCH: Duration = Duration::from_secs(300);

/// Time after which an unused URL is no longer refreshed.
const UNUSED_URL: Duration = Duration::from_secs(7 * 86_400);

/// Bounds the paths whose decisions the refresh computes in advance.
const MAXIMUM_KNOWN_PATHS: usize = 256;

/// Bounds the cached decisions.
const MAXIMUM_DECISIONS: usize = 1024;

/// Largest unverified CRL whose signature `decide` verifies inline.
///
/// A prefetched or cached CRL has no known issuer key until a path uses it.
/// Hashing and verifying a CRL of this size takes well under a millisecond,
/// so `decide` can do it in the TLS verify callback. Larger CRLs wait for
/// `obtain`, which verifies them on the blocking pool.
const INLINE_VERIFY_LIMIT: usize = 64 * 1024;

type PathKey = [u8; 32];
type FlightKey = (String, String);

/// Counters of one [`CrlVerifier`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CrlVerifierCounters {
    /// CRL fetch attempts.
    pub fetches: u64,
    /// CRL fetch attempts that failed, timed out, or returned an invalid CRL.
    pub fetch_failures: u64,
    /// Distribution point URLs skipped because an earlier fetch failed.
    pub backoffs: u64,
    /// Soft-fail decisions that accepted a CRL inside the grace period.
    pub stale_grace_accepts: u64,
    /// Warn-only decisions that accepted a server without evidence.
    pub warn_only_accepts: u64,
    /// Decisions that rejected a server because a CRL lists a certificate.
    pub revoked_rejects: u64,
    /// `decide` calls that returned `NeedEvidence`.
    pub evidence_misses: u64,
}

#[derive(Default)]
struct Counters {
    fetches: AtomicU64,
    fetch_failures: AtomicU64,
    backoffs: AtomicU64,
    stale_grace_accepts: AtomicU64,
    warn_only_accepts: AtomicU64,
    revoked_rejects: AtomicU64,
    evidence_misses: AtomicU64,
}

fn increment(counter: &AtomicU64, amount: usize) {
    counter.fetch_add(u64::try_from(amount).unwrap_or(u64::MAX), Ordering::Relaxed);
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct SettingsState {
    receiver: watch::Receiver<RevocationSettings>,
    current: Arc<RevocationSettings>,
    generation: u64,
}

struct CachedDecision {
    settings_generation: u64,
    store_generation: u64,
    decision: FinalDecision,
    created: Instant,
    sticky: bool,
}

struct KnownPath {
    path: VerifiedPath,
    seen: Instant,
}

#[derive(Default)]
struct DiskCacheLoad {
    directory: Option<PathBuf>,
    in_flight: Option<(PathBuf, watch::Receiver<Option<bool>>)>,
}

/// A [`RevocationVerifier`] that checks server certificate paths with CRLs.
///
/// `decide` answers from an in-memory decision cache and from CRLs whose
/// signatures were already verified. When evidence is missing, `obtain` fetches
/// CRLs over HTTP through the [`RevocationNetwork`] of the server, verifies
/// them on the blocking thread pool, and stores the decision. An optional
/// background task from [`CrlVerifier::spawn_refresh`] prefetches CRLs and
/// refreshes them before `nextUpdate`.
///
/// The verifier affects only new connections. It never closes an established
/// connection.
///
/// Clones share the same state.
#[derive(Clone)]
pub struct CrlVerifier {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    settings: Mutex<SettingsState>,
    store: Mutex<Store>,
    backoff: Mutex<Backoff>,
    decisions: Mutex<HashMap<PathKey, CachedDecision>>,
    known: Mutex<HashMap<PathKey, KnownPath>>,
    flights: Mutex<HashMap<FlightKey, watch::Receiver<Option<bool>>>>,
    disk_cache_load: Mutex<DiskCacheLoad>,
    counters: Counters,
    allow_loopback: bool,
}

impl std::fmt::Debug for CrlVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CrlVerifier")
            .field("counters", &self.counters())
            .finish_non_exhaustive()
    }
}

impl CrlVerifier {
    /// Creates a verifier that reads its policy from `settings`.
    ///
    /// A new value in `settings` applies to the next decision. It does not
    /// affect established connections. The verifier does not validate the
    /// settings; the host must call [`RevocationSettings::validate`] first.
    #[must_use]
    pub fn new(settings: watch::Receiver<RevocationSettings>) -> Self {
        Self::build(settings, false)
    }

    /// Creates a verifier that can fetch from loopback addresses.
    #[cfg(test)]
    pub(crate) fn with_loopback(settings: watch::Receiver<RevocationSettings>) -> Self {
        Self::build(settings, true)
    }

    fn build(mut receiver: watch::Receiver<RevocationSettings>, allow_loopback: bool) -> Self {
        let current = Arc::new(receiver.borrow_and_update().clone());
        Self {
            inner: Arc::new(Inner {
                settings: Mutex::new(SettingsState {
                    receiver,
                    current,
                    generation: 0,
                }),
                store: Mutex::default(),
                backoff: Mutex::default(),
                decisions: Mutex::default(),
                known: Mutex::default(),
                flights: Mutex::default(),
                disk_cache_load: Mutex::default(),
                counters: Counters::default(),
                allow_loopback,
            }),
        }
    }

    /// Starts the background refresh on the current Tokio runtime.
    ///
    /// The task loads the disk cache, fetches the prefetch URLs, and refreshes
    /// stored CRLs before their `nextUpdate`. It uses `network` for prefetch
    /// URLs and for URLs that no connection has used yet. Other URLs use the
    /// network of the last connection that needed them. The task ends when
    /// every clone of the verifier is dropped. Abort the handle to stop it
    /// earlier.
    #[must_use]
    pub fn spawn_refresh(&self, network: RevocationNetwork) -> JoinHandle<()> {
        let (_sender, receiver) = watch::channel(network);
        self.spawn_refresh_observed(receiver)
    }

    /// Starts the background refresh with a dynamically updated default network.
    ///
    /// A host uses this method so prefetch fetches inherit the VRF, egress
    /// binding, and connection guard of the active server configuration.
    #[must_use]
    pub fn spawn_refresh_observed(
        &self,
        mut network: watch::Receiver<RevocationNetwork>,
    ) -> JoinHandle<()> {
        let weak = Arc::downgrade(&self.inner);
        let mut changes = lock(&self.inner.settings).receiver.clone();
        let mut network_open = true;
        tokio::spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                let current_network = network.borrow_and_update().clone();
                let wait = inner.refresh_once(&current_network).await;
                drop(inner);
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    changed = changes.changed() => {
                        if changed.is_err() {
                            tokio::time::sleep(wait).await;
                        }
                    }
                    changed = network.changed(), if network_open => {
                        network_open = changed.is_ok();
                    }
                }
            }
        })
    }

    /// Returns the current counters.
    #[must_use]
    pub fn counters(&self) -> CrlVerifierCounters {
        let counters = &self.inner.counters;
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        CrlVerifierCounters {
            fetches: read(&counters.fetches),
            fetch_failures: read(&counters.fetch_failures),
            backoffs: read(&counters.backoffs),
            stale_grace_accepts: read(&counters.stale_grace_accepts),
            warn_only_accepts: read(&counters.warn_only_accepts),
            revoked_rejects: read(&counters.revoked_rejects),
            evidence_misses: read(&counters.evidence_misses),
        }
    }
}

#[async_trait]
impl RevocationVerifier for CrlVerifier {
    fn decide(&self, path: &VerifiedPath) -> RevocationDecision {
        self.inner.decide(path)
    }

    async fn obtain(
        &self,
        path: &VerifiedPath,
        network: &RevocationNetwork,
        deadline: Option<tokio::time::Instant>,
    ) {
        self.inner.obtain(path, network, deadline).await;
    }
}

fn path_key(path: &VerifiedPath) -> Option<PathKey> {
    let mut digests = Vec::with_capacity(path.certificates().len() * 32);
    for certificate in path.certificates() {
        digests.extend_from_slice(&certificate.digest(MessageDigest::sha256()).ok()?);
    }
    digest(&digests).ok()
}

impl Inner {
    fn settings(&self) -> (Arc<RevocationSettings>, u64) {
        let mut state = lock(&self.settings);
        if state.receiver.has_changed().unwrap_or(false) {
            let current = state.receiver.borrow_and_update().clone();
            state.current = Arc::new(current);
            state.generation += 1;
            log::info!("Revocation settings changed; enforcement is {}", state.current.enforcement);
        }
        (Arc::clone(&state.current), state.generation)
    }

    fn decide(&self, path: &VerifiedPath) -> RevocationDecision {
        let (settings, settings_generation) = self.settings();
        if !settings.enforcement.requires_verifier() {
            return RevocationDecision::Verified;
        }
        let key = path_key(path);
        if let Some(key) = key {
            if let Some(decision) = self.cached(&key, settings_generation) {
                return self.count(decision);
            }
        }
        let (outcome, generation) = self.evaluate(path, &settings, false);
        match outcome {
            Outcome::Final(decision) => {
                log_decision(path, &decision);
                if let Some(key) = key {
                    self.cache(key, settings_generation, generation, decision.clone(), false);
                }
                self.count(decision)
            }
            Outcome::Need(need) if need.prepare => {
                self.prepare_blocking(path, None, true);
                self.decide_after_prepare(path, key, &settings, settings_generation)
            }
            Outcome::Need(_) => {
                self.remember(key, path);
                increment(&self.counters.evidence_misses, 1);
                RevocationDecision::NeedEvidence
            }
        }
    }

    fn decide_after_prepare(
        &self,
        path: &VerifiedPath,
        key: Option<PathKey>,
        settings: &RevocationSettings,
        settings_generation: u64,
    ) -> RevocationDecision {
        match self.evaluate(path, settings, false) {
            (Outcome::Final(decision), generation) => {
                log_decision(path, &decision);
                if let Some(key) = key {
                    self.cache(key, settings_generation, generation, decision.clone(), false);
                }
                self.count(decision)
            }
            (Outcome::Need(_), _) => {
                self.remember(key, path);
                increment(&self.counters.evidence_misses, 1);
                RevocationDecision::NeedEvidence
            }
        }
    }

    fn count(&self, decision: FinalDecision) -> RevocationDecision {
        let counter = match decision.kind {
            DecisionKind::GraceAccept => Some(&self.counters.stale_grace_accepts),
            DecisionKind::WarnAccept => Some(&self.counters.warn_only_accepts),
            DecisionKind::Revoked => Some(&self.counters.revoked_rejects),
            DecisionKind::Verified | DecisionKind::Unverified => None,
        };
        if let Some(counter) = counter {
            increment(counter, 1);
        }
        decision.decision
    }

    fn cached(&self, key: &PathKey, settings_generation: u64) -> Option<FinalDecision> {
        let store_generation = lock(&self.store).generation();
        let decisions = lock(&self.decisions);
        let entry = decisions.get(key)?;
        let current = entry.store_generation == store_generation
            || (entry.sticky && entry.created.elapsed() < STICKY);
        (entry.settings_generation == settings_generation
            && current
            && SystemTime::now() < entry.decision.valid_until)
            .then(|| entry.decision.clone())
    }

    fn cache(
        &self,
        key: PathKey,
        settings_generation: u64,
        store_generation: u64,
        decision: FinalDecision,
        sticky: bool,
    ) {
        let mut decisions = lock(&self.decisions);
        if decisions.len() >= MAXIMUM_DECISIONS && !decisions.contains_key(&key) {
            decisions.clear();
        }
        decisions.insert(
            key,
            CachedDecision {
                settings_generation,
                store_generation,
                decision,
                created: Instant::now(),
                sticky,
            },
        );
    }

    fn remember(&self, key: Option<PathKey>, path: &VerifiedPath) {
        let Some(key) = key else {
            return;
        };
        let mut known = lock(&self.known);
        if known.len() >= MAXIMUM_KNOWN_PATHS && !known.contains_key(&key) {
            if let Some(oldest) = known
                .iter()
                .min_by_key(|(_, entry)| entry.seen)
                .map(|(key, _)| *key)
            {
                known.remove(&oldest);
            }
        }
        known.insert(
            key,
            KnownPath {
                path: path.clone(),
                seen: Instant::now(),
            },
        );
    }

    /// Evaluates `path` with the current evidence. Returns the outcome and the store generation.
    fn evaluate(
        &self,
        path: &VerifiedPath,
        settings: &RevocationSettings,
        final_only: bool,
    ) -> (Outcome, u64) {
        let store = lock(&self.store);
        let backoff = lock(&self.backoff);
        let evaluation = Evaluation {
            settings,
            store: &store,
            backoff: &backoff,
            now: SystemTime::now(),
            instant: Instant::now(),
            final_only,
        };
        let (outcome, skipped) = evaluation.evaluate(path.certificates());
        increment(&self.counters.backoffs, skipped);
        (outcome, store.generation())
    }

    async fn obtain(
        self: &Arc<Self>,
        path: &VerifiedPath,
        network: &RevocationNetwork,
        deadline: Option<tokio::time::Instant>,
    ) {
        let (settings, _) = self.settings();
        if !settings.enforcement.requires_verifier() {
            return;
        }
        // A host without the refresh task, such as a CLI, still uses the disk cache.
        let load = self.load_disk(&settings);
        if let Some(deadline) = deadline {
            if tokio::time::timeout_at(deadline, load).await.is_err() {
                log::debug!("CRL cache loading exceeded the connection deadline");
                return;
            }
        } else {
            load.await;
        }
        let key = path_key(path);
        self.remember(key, path);
        for _ in 0..MAXIMUM_ROUNDS {
            self.prepare(path, Some(network)).await;
            let (settings, _) = self.settings();
            let need = match self.evaluate(path, &settings, false).0 {
                Outcome::Final(_) => break,
                Outcome::Need(need) => need,
            };
            for group in &need.fetch {
                self.fetch_group(group, network, deadline).await;
            }
            if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                break;
            }
        }
        let (settings, settings_generation) = self.settings();
        if let (Outcome::Final(decision), generation) = self.evaluate(path, &settings, true) {
            log_decision(path, &decision);
            if let Some(key) = key {
                self.cache(key, settings_generation, generation, decision, true);
            }
        }
    }

    /// Verifies unverified candidate CRLs for `path` on the blocking pool.
    async fn prepare(self: &Arc<Self>, path: &VerifiedPath, network: Option<&RevocationNetwork>) {
        let inner = Arc::clone(self);
        let path = path.clone();
        let network = network.cloned();
        if let Err(error) = tokio::task::spawn_blocking(move || {
            inner.prepare_blocking(&path, network.as_ref(), false)
        })
        .await
        {
            log::warn!("CRL verification task failed: {error}");
        }
    }

    /// Verifies candidate CRLs for `path` against the issuer keys in the path.
    ///
    /// With `inline`, the call comes from `decide`: it verifies only small
    /// CRLs and does not write the disk cache.
    fn prepare_blocking(
        &self,
        path: &VerifiedPath,
        network: Option<&RevocationNetwork>,
        inline: bool,
    ) {
        let (settings, _) = self.settings();
        for pair in path.certificates().windows(2) {
            let (certificate, issuer) = (&pair[0], &pair[1]);
            let Ok(info) = CertificateInfo::read(certificate) else {
                continue;
            };
            let Ok(key) = issuer.public_key() else {
                continue;
            };
            let Ok(key_der) = key.public_key_to_der() else {
                continue;
            };
            let points = allowed_urls(&info.distribution_points, &settings);
            let mut uris = info.freshest.clone();
            {
                let store = lock(&self.store);
                for url in &points {
                    if let Some(entry) = store.entry(url.as_str()) {
                        let crls = entry
                            .verified
                            .iter()
                            .map(|verified| &verified.crl)
                            .chain(entry.candidate.as_ref().map(|candidate| &candidate.crl));
                        for crl in crls {
                            uris.extend(crl.freshest.iter().cloned());
                        }
                    }
                }
            }
            let mut urls = points;
            for url in allowed_urls(&uris, &settings) {
                if !urls.contains(&url) {
                    urls.push(url);
                }
            }
            for url in urls {
                let candidate = {
                    let mut store = lock(&self.store);
                    store.touch(url.as_str(), network);
                    store.candidate(url.as_str(), &key_der).cloned()
                };
                if let Some(crl) = candidate {
                    if inline && crl.der.len() > INLINE_VERIFY_LIMIT {
                        continue;
                    }
                    let persist = (!inline).then_some(&*settings);
                    self.verify_and_promote(url.as_str(), &key, &key_der, &crl, persist);
                }
            }
        }
    }

    fn verify_and_promote(
        &self,
        url: &str,
        key: &PKey<Public>,
        key_der: &[u8],
        crl: &Arc<Crl>,
        persist: Option<&RevocationSettings>,
    ) -> bool {
        if !crl.crl.verify(key).unwrap_or(false) {
            log::debug!("The CRL from {url} does not match an issuer key");
            lock(&self.store).reject_candidate(url, &crl.digest, key_der);
            return false;
        }
        let promoted = lock(&self.store).promote(url, key, key_der, crl);
        match promoted {
            Ok(changed) => {
                if let (true, Some(settings)) = (changed, persist) {
                    self.persist(url, crl, Some(key_der), settings);
                }
                true
            }
            Err(error) => {
                log::warn!("{error:#}");
                false
            }
        }
    }

    fn persist(&self, url: &str, crl: &Crl, key_der: Option<&[u8]>, settings: &RevocationSettings) {
        if let Some(directory) = &settings.cache_directory {
            if let Err(error) = disk::write(directory, url, crl, key_der, settings.max_crl_bytes) {
                log::warn!("{error:#}");
            }
        }
    }

    /// Tries the mirrors of one group in order until one fetch succeeds.
    async fn fetch_group(
        self: &Arc<Self>,
        group: &[DistributionPointUrl],
        network: &RevocationNetwork,
        deadline: Option<tokio::time::Instant>,
    ) -> bool {
        for url in group {
            let blocked = lock(&self.backoff)
                .blocked_until(url.as_str(), Instant::now())
                .is_some();
            if blocked {
                increment(&self.counters.backoffs, 1);
                log::debug!("Skipped CRL distribution point {url} during back-off");
                continue;
            }
            let mut flight = self.flight(url, network);
            let wait = async move {
                flight
                    .wait_for(Option::is_some)
                    .await
                    .is_ok_and(|result| *result == Some(true))
            };
            let succeeded = match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, wait)
                    .await
                    .unwrap_or(false),
                None => wait.await,
            };
            if succeeded {
                return true;
            }
            if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                return false;
            }
        }
        false
    }

    /// Returns the shared fetch of `url` through `network`, and starts it if needed.
    ///
    /// The fetch runs in its own task, so a dropped waiter does not cancel it.
    fn flight(
        self: &Arc<Self>,
        url: &DistributionPointUrl,
        network: &RevocationNetwork,
    ) -> watch::Receiver<Option<bool>> {
        let key = (url.as_str().to_owned(), format!("{:?}", network.binding()));
        let mut flights = lock(&self.flights);
        if let Some(receiver) = flights.get(&key) {
            return receiver.clone();
        }
        let (sender, receiver) = watch::channel(None);
        flights.insert(key.clone(), receiver.clone());
        drop(flights);
        let inner = Arc::clone(self);
        let url = url.clone();
        let network = network.clone();
        tokio::spawn(async move {
            let succeeded = inner.run_fetch(&url, &network).await;
            lock(&inner.flights).remove(&key);
            let _ = sender.send(Some(succeeded));
        });
        receiver
    }

    async fn run_fetch(
        self: &Arc<Self>,
        url: &DistributionPointUrl,
        network: &RevocationNetwork,
    ) -> bool {
        let (settings, _) = self.settings();
        increment(&self.counters.fetches, 1);
        lock(&self.store).record_fetch(url.as_str());
        let allow_private = settings.allow_private_addresses;
        let allow_loopback = self.allow_loopback;
        let filter = move |address: SocketAddr| -> Result<()> {
            if allow_loopback && address.ip().to_canonical().is_loopback() {
                return Ok(());
            }
            check_address(address, allow_private)
        };
        log::debug!("Fetching CRL from {url}");
        let body = match tokio::time::timeout(
            settings.fetch_timeout,
            fetch::fetch(url, network, &filter, settings.max_crl_bytes),
        )
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(error)) => return self.fail(url, &error),
            Err(_) => {
                let error =
                    anyhow!("CRL fetch from {url} timed out after {:?}", settings.fetch_timeout);
                return self.fail(url, &error);
            }
        };
        let inner = Arc::clone(self);
        let stored_url = url.as_str().to_owned();
        let stored =
            tokio::task::spawn_blocking(move || inner.store_fetched(&stored_url, &body, &settings))
                .await
                .map_err(|error| anyhow!("CRL processing task failed: {error}"))
                .and_then(|result| result);
        match stored {
            Ok(true) => {
                lock(&self.backoff).record_success(url.as_str());
                true
            }
            Ok(false) => {
                let delay = lock(&self.backoff).record_failure(url.as_str());
                log::warn!(
                    "CRL distribution point {url} returned a CRL past its nextUpdate; retrying after {delay:?}"
                );
                true
            }
            Err(error) => self.fail(url, &error),
        }
    }

    fn fail(&self, url: &DistributionPointUrl, error: &anyhow::Error) -> bool {
        increment(&self.counters.fetch_failures, 1);
        let delay = lock(&self.backoff).record_failure(url.as_str());
        log::warn!("CRL fetch from {url} failed; retrying after {delay:?}: {error:#}");
        false
    }

    /// Parses and stores a fetched CRL. Returns whether the CRL is fresh.
    fn store_fetched(&self, url: &str, body: &[u8], settings: &RevocationSettings) -> Result<bool> {
        let crl = Arc::new(Crl::parse(body)?);
        lock(&self.store).record_stored(url);
        let fresh = crl.next_update.is_some_and(|next| SystemTime::now() < next);
        let keys = lock(&self.store).known_keys(url);
        for (key, key_der) in keys {
            if crl.crl.verify(&key).unwrap_or(false) {
                self.verify_and_promote(url, &key, &key_der, &crl, Some(settings));
                return Ok(fresh);
            }
        }
        if lock(&self.store).insert_candidate(url, Arc::clone(&crl)) {
            self.persist(url, &crl, None, settings);
        }
        Ok(fresh)
    }

    /// Runs one refresh round and returns the time until the next round.
    pub(crate) async fn refresh_once(self: &Arc<Self>, network: &RevocationNetwork) -> Duration {
        let (settings, _) = self.settings();
        if !settings.enforcement.requires_verifier() {
            return REFRESH_INTERVAL;
        }
        self.load_disk(&settings).await;
        let before = lock(&self.store).generation();
        for (url, url_network) in self.due(&settings, network) {
            let blocked = lock(&self.backoff)
                .blocked_until(url.as_str(), Instant::now())
                .is_some();
            if blocked {
                continue;
            }
            let mut flight = self.flight(&url, &url_network);
            let _ = flight.wait_for(Option::is_some).await;
        }
        if lock(&self.store).generation() != before {
            self.recompute().await;
        }
        REFRESH_INTERVAL
    }

    fn due(
        &self,
        settings: &RevocationSettings,
        network: &RevocationNetwork,
    ) -> Vec<(DistributionPointUrl, RevocationNetwork)> {
        let store = lock(&self.store);
        let now = SystemTime::now();
        let is_due = |url: &str| {
            let Some(entry) = store.entry(url) else {
                return true;
            };
            let Some(crl) = entry.newest() else {
                return true;
            };
            refresh_time(crl) <= now
                && entry
                    .last_fetch
                    .is_none_or(|last| last.elapsed() >= MINIMUM_REFETCH)
        };
        let mut due: Vec<(DistributionPointUrl, RevocationNetwork)> = Vec::new();
        for url in &settings.prefetch_distribution_points {
            if settings.allows(url) && is_due(url.as_str()) {
                due.push((url.clone(), network.clone()));
            }
        }
        for (text, entry) in store.urls() {
            if entry.last_used.elapsed() > UNUSED_URL {
                continue;
            }
            let Ok(url) = DistributionPointUrl::parse(text) else {
                continue;
            };
            if settings.allows(&url)
                && is_due(text)
                && !due.iter().any(|(existing, _)| existing == &url)
            {
                let url_network = entry.network.clone().unwrap_or_else(|| network.clone());
                due.push((url, url_network));
            }
        }
        due
    }

    async fn load_disk(self: &Arc<Self>, settings: &Arc<RevocationSettings>) {
        let directory = settings.cache_directory.clone();
        loop {
            let (loading_directory, mut flight) = {
                let mut state = lock(&self.disk_cache_load);
                if state.directory == directory {
                    return;
                }
                if let Some((path, flight)) = &state.in_flight {
                    (path.clone(), flight.clone())
                } else if let Some(path) = directory.clone() {
                    let (sender, receiver) = watch::channel(None);
                    state.in_flight = Some((path.clone(), receiver.clone()));
                    let inner = Arc::clone(self);
                    let settings = Arc::clone(settings);
                    let loading_directory = path.clone();
                    tokio::spawn(async move {
                        let loader = Arc::clone(&inner);
                        let load_path = path.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            loader.load_disk_blocking(&load_path, &settings);
                        })
                        .await;
                        if let Err(error) = &result {
                            log::warn!("CRL cache load task failed: {error}");
                        }
                        {
                            let mut state = lock(&inner.disk_cache_load);
                            if result.is_ok() {
                                state.directory = Some(path);
                            }
                            state.in_flight = None;
                        }
                        let _ = sender.send(Some(result.is_ok()));
                    });
                    (loading_directory, receiver)
                } else {
                    state.directory = None;
                    return;
                }
            };
            if let Err(error) = flight.wait_for(Option::is_some).await {
                log::warn!("CRL cache load task ended without a result: {error}");
                return;
            }
            if directory.as_ref() == Some(&loading_directory) {
                return;
            }
        }
    }

    fn load_disk_blocking(&self, directory: &std::path::Path, settings: &RevocationSettings) {
        let files = disk::load(directory, settings.max_crl_bytes);
        let mut loaded = 0usize;
        for file in files {
            match DistributionPointUrl::parse(&file.url) {
                Ok(url) if settings.allows(&url) => {}
                _ => continue,
            }
            let newer_in_memory = lock(&self.store)
                .entry(&file.url)
                .and_then(|entry| entry.newest())
                .is_some_and(|existing| existing.recency(&file.crl).is_ge());
            if newer_in_memory {
                continue;
            }
            let crl = Arc::new(file.crl);
            let key = file
                .key_der
                .as_deref()
                .and_then(|der| PKey::public_key_from_der(der).ok().map(|key| (key, der)));
            let verified = key.is_some_and(|(key, der)| {
                crl.crl.verify(&key).unwrap_or(false)
                    && lock(&self.store)
                        .promote(&file.url, &key, der, &crl)
                        .is_ok()
            });
            if !verified {
                lock(&self.store).insert_candidate(&file.url, crl);
            }
            loaded += 1;
        }
        log::info!("Loaded {loaded} CRLs from the cache {}", directory.display());
    }

    /// Computes decisions for recently seen paths after the evidence changed.
    async fn recompute(self: &Arc<Self>) {
        let paths: Vec<(PathKey, VerifiedPath)> = lock(&self.known)
            .iter()
            .map(|(key, known)| (*key, known.path.clone()))
            .collect();
        let inner = Arc::clone(self);
        let result = tokio::task::spawn_blocking(move || {
            for (key, path) in paths {
                inner.prepare_blocking(&path, None, false);
                let (settings, settings_generation) = inner.settings();
                if let (Outcome::Final(decision), generation) =
                    inner.evaluate(&path, &settings, false)
                {
                    inner.cache(key, settings_generation, generation, decision, false);
                }
            }
        })
        .await;
        if let Err(error) = result {
            log::warn!("CRL decision task failed: {error}");
        }
    }
}

/// Returns when the refresh should fetch a newer CRL.
fn refresh_time(crl: &Crl) -> SystemTime {
    let Some(next) = crl.next_update else {
        return crl.this_update + Duration::from_secs(3600);
    };
    let window = next
        .duration_since(crl.this_update)
        .unwrap_or(Duration::ZERO);
    let margin = (window / 10).clamp(Duration::from_secs(60), Duration::from_secs(3600));
    let planned = next.checked_sub(margin).unwrap_or(next);
    match crl.next_publish {
        Some(publish) if publish < planned => publish,
        _ => planned,
    }
}

fn log_decision(path: &VerifiedPath, decision: &FinalDecision) {
    let server = path.peer_identity();
    match &decision.decision {
        RevocationDecision::Verified => {
            log::debug!("CRLs verified the certificate path of {server}");
        }
        RevocationDecision::Accept(reason) => {
            log::warn!("Revocation policy accepted {server}: {reason}");
        }
        RevocationDecision::Reject(rejection) => {
            log::warn!("Revocation check rejected {server}: {}", rejection.reason());
        }
        RevocationDecision::NeedEvidence => {}
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::sync::mpsc;
    use std::task::Poll;
    use tacacsrs_networking::{DistributionPointPattern, RevocationEnforcement, RevocationSettings};

    use super::*;
    use crate::tests::pki::{CertificateOptions, CrlOptions, crl, issue, key};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_cache_loads_wait_for_the_first_load() {
        let url = "http://crl.example.test/root.crl";
        let issuer = issue(
            "Cache Root",
            key(),
            None,
            &CertificateOptions {
                ca: true,
                serial: 1,
                ..CertificateOptions::default()
            },
        );
        let leaf = issue(
            "server.example.test",
            key(),
            Some(&issuer),
            &CertificateOptions {
                serial: 2,
                distribution_points: &[url],
                ..CertificateOptions::default()
            },
        );
        let path = VerifiedPath::new(
            vec![leaf.certificate, issuer.certificate.clone()],
            "server.example.test",
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut settings = RevocationSettings::default();
        settings.enforcement = RevocationEnforcement::HardFail;
        settings.allowed_distribution_points =
            vec![DistributionPointPattern::parse("http://crl.example.test/**").unwrap()];
        settings.cache_directory = Some(directory.path().to_path_buf());
        let crl = Crl::parse(&crl(&issuer, &CrlOptions::default())).unwrap();
        disk::write(
            directory.path(),
            url,
            &crl,
            Some(&issuer.key.public_key_to_der().unwrap()),
            settings.max_crl_bytes,
        )
        .unwrap();
        let (_sender, receiver) = watch::channel(settings.clone());
        let verifier = CrlVerifier::new(receiver);
        let settings = Arc::new(settings);

        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let inner = Arc::clone(&verifier.inner);
        let holder = std::thread::spawn(move || {
            let _guard = lock(&inner.store);
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let mut first = Box::pin(verifier.inner.load_disk(&settings));
        let first_pending = poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx).is_pending())).await;
        let mut second = Box::pin(verifier.inner.load_disk(&settings));
        let second_pending = poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx).is_pending())).await;

        drop(first);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let timely = tokio::time::timeout(
            Duration::from_secs(2),
            verifier.obtain(&path, &RevocationNetwork::default(), Some(deadline)),
        )
        .await
        .is_ok();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        if second_pending {
            second.await;
        }
        assert!(first_pending, "the first load must wait for the cache");
        assert!(second_pending, "later loads must wait for the first load");
        assert!(timely, "cache loading must respect the connection deadline");
        assert_eq!(verifier.decide(&path), RevocationDecision::Verified);
    }
}
