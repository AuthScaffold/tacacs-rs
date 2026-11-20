//! In-memory CRL evidence keyed by distribution point URL, and fetch back-off.
//!
//! Each URL has a list of CRLs whose signatures were verified, one per issuer
//! key, and at most one unverified candidate. A candidate comes from a fetch,
//! a prefetch, or the disk cache. It becomes verified evidence only after its
//! signature matches the key of the issuer certificate in a verified path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use openssl::pkey::{PKey, Public};
use tacacsrs_networking::RevocationNetwork;

use crate::crl::Crl;

/// Bounds the number of distribution point URLs kept in memory.
const MAXIMUM_URLS: usize = 512;

/// Bounds the number of issuer keys kept for one URL.
const MAXIMUM_KEYS_PER_URL: usize = 4;

/// First back-off delay after a failed fetch.
pub(crate) const INITIAL_BACKOFF: Duration = Duration::from_secs(30);

/// Largest back-off delay.
pub(crate) const MAXIMUM_BACKOFF: Duration = Duration::from_secs(600);

/// A CRL whose signature matches an issuer key.
pub(crate) struct VerifiedCrl {
    pub(crate) key: PKey<Public>,
    pub(crate) key_der: Vec<u8>,
    pub(crate) crl: Arc<Crl>,
}

/// A CRL whose signature is not verified yet.
pub(crate) struct Candidate {
    pub(crate) crl: Arc<Crl>,
    rejected_keys: Vec<Vec<u8>>,
}

/// Evidence for one distribution point URL.
pub(crate) struct UrlEntry {
    pub(crate) verified: Vec<VerifiedCrl>,
    pub(crate) candidate: Option<Candidate>,
    pub(crate) network: Option<RevocationNetwork>,
    pub(crate) last_used: Instant,
    pub(crate) last_fetch: Option<Instant>,
    /// Time of the last fetch that returned a parseable CRL.
    pub(crate) last_stored: Option<Instant>,
}

impl UrlEntry {
    fn new() -> Self {
        Self {
            verified: Vec::new(),
            candidate: None,
            network: None,
            last_used: Instant::now(),
            last_fetch: None,
            last_stored: None,
        }
    }

    /// Returns the most recent CRL in this entry, verified or not.
    pub(crate) fn newest(&self) -> Option<&Arc<Crl>> {
        self.verified
            .iter()
            .map(|entry| &entry.crl)
            .chain(self.candidate.as_ref().map(|candidate| &candidate.crl))
            .max_by(|left, right| left.recency(right))
    }
}

/// The CRL evidence of one verifier.
#[derive(Default)]
pub(crate) struct Store {
    entries: HashMap<String, UrlEntry>,
    generation: u64,
}

impl Store {
    /// Returns a counter that changes whenever the evidence changes.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn entry(&self, url: &str) -> Option<&UrlEntry> {
        self.entries.get(url)
    }

    pub(crate) fn urls(&self) -> impl Iterator<Item = (&String, &UrlEntry)> {
        self.entries.iter()
    }

    fn entry_mut(&mut self, url: &str) -> &mut UrlEntry {
        if !self.entries.contains_key(url) && self.entries.len() >= MAXIMUM_URLS {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(url, _)| url.clone())
            {
                log::debug!("Evicted CRL evidence for {oldest} because the cache is full");
                self.entries.remove(&oldest);
            }
        }
        self.entries
            .entry(url.to_owned())
            .or_insert_with(UrlEntry::new)
    }

    /// Returns the verified CRL for `url` and the issuer key.
    pub(crate) fn verified(&self, url: &str, key_der: &[u8]) -> Option<&Arc<Crl>> {
        self.entries.get(url).and_then(|entry| {
            entry
                .verified
                .iter()
                .find(|verified| verified.key_der == key_der)
                .map(|verified| &verified.crl)
        })
    }

    /// Returns the candidate for `url` if its signature was not checked with the key.
    pub(crate) fn candidate(&self, url: &str, key_der: &[u8]) -> Option<&Arc<Crl>> {
        self.entries
            .get(url)
            .and_then(|entry| entry.candidate.as_ref())
            .filter(|candidate| {
                !candidate
                    .rejected_keys
                    .iter()
                    .any(|rejected| rejected == key_der)
            })
            .map(|candidate| &candidate.crl)
    }

    /// Returns the issuer keys that verified earlier CRLs from `url`.
    pub(crate) fn known_keys(&self, url: &str) -> Vec<(PKey<Public>, Vec<u8>)> {
        self.entries
            .get(url)
            .map(|entry| {
                entry
                    .verified
                    .iter()
                    .map(|verified| (verified.key.clone(), verified.key_der.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Marks `url` as used by a connection.
    pub(crate) fn touch(&mut self, url: &str, network: Option<&RevocationNetwork>) {
        let entry = self.entry_mut(url);
        entry.last_used = Instant::now();
        if let Some(network) = network {
            entry.network = Some(network.clone());
        }
    }

    /// Records a fetch attempt for `url`.
    pub(crate) fn record_fetch(&mut self, url: &str) {
        self.entry_mut(url).last_fetch = Some(Instant::now());
    }

    /// Records that a fetch of `url` returned a parseable CRL.
    pub(crate) fn record_stored(&mut self, url: &str) {
        self.entry_mut(url).last_stored = Some(Instant::now());
    }

    /// Stores an unverified CRL for `url`. Returns whether the store changed.
    pub(crate) fn insert_candidate(&mut self, url: &str, crl: Arc<Crl>) -> bool {
        let entry = self.entry_mut(url);
        let known = entry
            .verified
            .iter()
            .map(|verified| &verified.crl)
            .chain(entry.candidate.as_ref().map(|candidate| &candidate.crl))
            .any(|existing| existing.digest == crl.digest);
        if known {
            return false;
        }
        entry.candidate = Some(Candidate {
            crl,
            rejected_keys: Vec::new(),
        });
        self.generation += 1;
        true
    }

    /// Stores `crl` as verified evidence for the issuer key.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored CRL for the same key is more recent.
    /// The verifier never replaces evidence with older evidence.
    pub(crate) fn promote(
        &mut self,
        url: &str,
        key: &PKey<Public>,
        key_der: &[u8],
        crl: &Arc<Crl>,
    ) -> Result<bool> {
        let entry = self.entry_mut(url);
        if entry
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.crl.digest == crl.digest)
        {
            entry.candidate = None;
        }
        if let Some(existing) = entry
            .verified
            .iter_mut()
            .find(|verified| verified.key_der == key_der)
        {
            if existing.crl.digest == crl.digest {
                return Ok(false);
            }
            if existing.crl.recency(crl).is_gt() {
                self.generation += 1;
                bail!("Rejected a CRL from {url} that is older than the stored CRL");
            }
            existing.crl = Arc::clone(crl);
        } else {
            if entry.verified.len() >= MAXIMUM_KEYS_PER_URL {
                entry.verified.remove(0);
            }
            entry.verified.push(VerifiedCrl {
                key: key.clone(),
                key_der: key_der.to_vec(),
                crl: Arc::clone(crl),
            });
        }
        self.generation += 1;
        Ok(true)
    }

    /// Records that the candidate `digest` at `url` does not match the key.
    pub(crate) fn reject_candidate(&mut self, url: &str, digest: &[u8; 32], key_der: &[u8]) {
        if let Some(candidate) = self
            .entries
            .get_mut(url)
            .and_then(|entry| entry.candidate.as_mut())
            .filter(|candidate| &candidate.crl.digest == digest)
        {
            candidate.rejected_keys.push(key_der.to_vec());
            self.generation += 1;
        }
    }
}

/// Failure state of one URL.
struct BackoffState {
    failures: u32,
    until: Instant,
}

/// Per-URL back-off after failed fetches.
#[derive(Default)]
pub(crate) struct Backoff {
    urls: HashMap<String, BackoffState>,
}

impl Backoff {
    /// Returns the end of the back-off for `url`, if it is still active.
    pub(crate) fn blocked_until(&self, url: &str, now: Instant) -> Option<Instant> {
        self.urls
            .get(url)
            .map(|state| state.until)
            .filter(|until| *until > now)
    }

    /// Records a failed fetch and returns the new delay.
    pub(crate) fn record_failure(&mut self, url: &str) -> Duration {
        let state = self.urls.entry(url.to_owned()).or_insert(BackoffState {
            failures: 0,
            until: Instant::now(),
        });
        state.failures = state.failures.saturating_add(1);
        let shift = state.failures.saturating_sub(1).min(16);
        let delay = INITIAL_BACKOFF
            .saturating_mul(1 << shift)
            .min(MAXIMUM_BACKOFF);
        state.until = Instant::now() + delay;
        delay
    }

    /// Clears the back-off for `url`.
    pub(crate) fn record_success(&mut self, url: &str) {
        self.urls.remove(url);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_limit() {
        let mut backoff = Backoff::default();
        let delays: Vec<_> = (0..7).map(|_| backoff.record_failure("u")).collect();
        assert_eq!(delays, [30, 60, 120, 240, 480, 600, 600].map(Duration::from_secs));
        assert!(backoff.blocked_until("u", Instant::now()).is_some());
        backoff.record_success("u");
        assert!(backoff.blocked_until("u", Instant::now()).is_none());
    }
}
