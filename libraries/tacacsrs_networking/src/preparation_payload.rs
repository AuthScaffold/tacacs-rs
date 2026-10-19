//! Rust payload reservations for native endpoint preparation.

use std::sync::{Arc, Mutex};

/// Admission for Rust-owned preparation bytes, independent of a runtime or schema.
pub trait PreparationPayloadLedger: std::fmt::Debug + Send + Sync {
    /// Reserves bytes before a known allocation or at an opaque native handoff.
    /// # Errors
    /// Returns an error when the reservation exceeds the candidate limit.
    fn reserve(&self, bytes: u64) -> anyhow::Result<()>;

    /// Releases a reservation after its payload is disposed.
    fn release(&self, bytes: u64);
}

#[derive(Debug, Default)]
struct PayloadOwner {
    ledger: Option<Arc<dyn PreparationPayloadLedger>>,
    retained: Mutex<u64>,
}

impl Drop for PayloadOwner {
    fn drop(&mut self) {
        if let Some(ledger) = &self.ledger {
            ledger.release(
                *self
                    .retained
                    .get_mut()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
        }
    }
}

/// Shared accounting for one prepared endpoint, including Rust native callbacks.
#[derive(Clone, Debug, Default)]
pub struct PreparationPayload(Arc<PayloadOwner>);

impl PreparationPayload {
    /// Creates an endpoint owner backed by the caller's candidate ledger.
    #[must_use]
    pub fn new(ledger: Arc<dyn PreparationPayloadLedger>) -> Self {
        Self(Arc::new(PayloadOwner {
            ledger: Some(ledger),
            retained: Mutex::new(0),
        }))
    }

    /// Reserves retained bytes before copying them into this endpoint.
    /// # Errors
    /// Returns an error for overflow or exceeded admission.
    pub fn retain(&self, bytes: usize) -> anyhow::Result<()> {
        let bytes = u64::try_from(bytes)?;
        let mut retained = self
            .0
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = retained
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("prepared payload size overflow"))?;
        if let Some(ledger) = &self.0.ledger {
            ledger.reserve(bytes)?;
        }
        *retained = next;
        Ok(())
    }

    /// Returns the retained Rust payload charged to this shared endpoint owner.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        *self
            .0
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn temporary(&self, bytes: usize) -> anyhow::Result<PayloadReservation> {
        self.retain(bytes)?;
        Ok(PayloadReservation {
            owner: self.clone(),
            bytes: u64::try_from(bytes)?,
        })
    }

    pub(crate) fn native_bytes<Error: Into<anyhow::Error>>(
        &self,
        known: usize,
        encode: impl FnOnce() -> Result<Vec<u8>, Error>,
    ) -> anyhow::Result<PayloadBytes> {
        let mut reservation = self.temporary(known)?;
        let bytes = encode().map_err(Into::into)?;
        let actual = u64::try_from(bytes.len())?;
        if actual > reservation.bytes {
            self.retain(usize::try_from(actual - reservation.bytes)?)?;
        } else {
            self.release(reservation.bytes - actual);
        }
        reservation.bytes = actual;
        Ok(PayloadBytes {
            bytes,
            _reservation: reservation,
        })
    }

    fn release(&self, bytes: u64) {
        let mut retained = self
            .0
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *retained = retained
            .checked_sub(bytes)
            .expect("prepared payload was reserved");
        if let Some(ledger) = &self.0.ledger {
            ledger.release(bytes);
        }
    }
}

pub(crate) struct PayloadReservation {
    owner: PreparationPayload,
    bytes: u64,
}

impl Drop for PayloadReservation {
    fn drop(&mut self) {
        self.owner.release(self.bytes);
    }
}

pub(crate) struct PayloadBytes {
    bytes: Vec<u8>,
    _reservation: PayloadReservation,
}

impl PayloadBytes {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
impl From<Vec<u8>> for PayloadBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            _reservation: PreparationPayload::default()
                .temporary(bytes.len())
                .unwrap(),
            bytes,
        }
    }
}

impl PartialEq for PayloadBytes {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for PayloadBytes {}

impl PartialOrd for PayloadBytes {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PayloadBytes {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Ledger {
        limit: u64,
        counts: Mutex<(u64, u64)>,
    }

    impl PreparationPayloadLedger for Ledger {
        fn reserve(&self, bytes: u64) -> anyhow::Result<()> {
            let mut counts = self.counts.lock().unwrap();
            let next = counts
                .0
                .checked_add(bytes)
                .ok_or_else(|| anyhow::anyhow!("overflow"))?;
            anyhow::ensure!(next <= self.limit, "limit");
            counts.0 = next;
            counts.1 = counts.1.max(next);
            Ok(())
        }

        fn release(&self, bytes: u64) {
            let mut counts = self.counts.lock().unwrap();
            counts.0 = counts.0.checked_sub(bytes).unwrap();
        }
    }

    #[test]
    fn retained_and_temporary_payload_share_exact_limit_and_drop_order() {
        for limit in [9, 10] {
            let ledger = Arc::new(Ledger {
                limit,
                counts: Mutex::new((0, 0)),
            });
            let payload = PreparationPayload::new(ledger.clone());
            payload.retain(5).unwrap();
            let called = std::sync::atomic::AtomicBool::new(false);
            let temporary = payload.native_bytes(5, || {
                called.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, anyhow::Error>(vec![7; 5])
            });
            assert_eq!(temporary.is_ok(), limit == 10);
            assert_eq!(called.load(std::sync::atomic::Ordering::SeqCst), limit == 10);
            drop(temporary);
            assert_eq!(payload.retained_bytes(), 5);
            assert_eq!(
                *ledger.counts.lock().unwrap(),
                (
                    5,
                    if limit == 10 {
                        10
                    } else {
                        5
                    }
                )
            );
            let shared = payload.clone();
            drop(payload);
            assert_eq!(ledger.counts.lock().unwrap().0, 5);
            drop(shared);
            assert_eq!(ledger.counts.lock().unwrap().0, 0);
        }
    }

    #[test]
    fn native_handoff_rejection_and_unwind_release_every_reservation() {
        let ledger = Arc::new(Ledger {
            limit: 8,
            counts: Mutex::new((0, 0)),
        });
        let payload = PreparationPayload::new(ledger.clone());
        assert!(payload
            .native_bytes(0, || Ok::<_, anyhow::Error>(vec![7; 9]))
            .is_err());
        assert_eq!(ledger.counts.lock().unwrap().0, 0);
        assert!(payload
            .native_bytes(8, || Err::<Vec<u8>, _>(anyhow::anyhow!("native failure")))
            .is_err());
        assert_eq!(ledger.counts.lock().unwrap().0, 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _reservation = payload.temporary(8).unwrap();
            panic!("native unwind");
        }));
        assert!(result.is_err());
        assert_eq!(ledger.counts.lock().unwrap().0, 0);
    }
}
