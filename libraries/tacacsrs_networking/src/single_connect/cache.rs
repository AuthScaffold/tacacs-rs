//! Shared-connection cache ownership for single-connection promotion.
//!
//! [`SharedConnectionCache`] is the single owner of the promoted shared
//! [`MultiplexedConnection`]. It keeps the cache slot, the epoch counter, the
//! closed flag, and the retiring list private so that no other scope can publish
//! a connection without passing through the guarded [`publish_if_current`] fence.
//!
//! # Publication fence
//!
//! A deferred promotion races against client shutdown and against a newer
//! negotiation epoch. The cache resolves both races under one write lock:
//!
//! ```text
//! acquire slot write lock
//!     |
//!     v
//! closed, or caller epoch != current epoch?
//!     |
//!     +-- yes --> drop the candidate connection, publish nothing
//!     |
//!     +-- no ---> upgrade the dedicated connection and store it
//! ```
//!
//! The closed flag and epoch are read while the write lock is held and *before*
//! the dedicated connection is upgraded, so a concurrent close or retirement can
//! never be overwritten by a late promotion.
//!
//! [`publish_if_current`]: SharedConnectionCache::publish_if_current

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::RwLock;

use crate::RequestDeadline;
use crate::connection::MultiplexedConnection;

/// Owns the cached shared connection and retires it when the last owner drops.
///
/// The client holds this as a capability. It never reaches into the slot, epoch,
/// or retiring list directly; it calls the methods below instead.
#[derive(Default)]
pub(crate) struct SharedConnectionCache {
    /// The currently published shared connection, if negotiation promoted one.
    slot: RwLock<Option<Arc<MultiplexedConnection>>>,
    /// Epoch counter that invalidates promotions captured before a retirement.
    generation: AtomicU64,
    /// Set once the client closes; blocks any further publication.
    closed: AtomicBool,
    /// Connections removed from the slot that still have sessions draining.
    retiring: Mutex<Vec<Arc<MultiplexedConnection>>>,
}

impl SharedConnectionCache {
    /// Returns the current epoch so a negotiation can detect later retirements.
    ///
    /// A promotion captures this value when it starts and presents it to
    /// [`Self::publish_if_current`] when the session completes.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Permanently blocks publication after the client closes.
    pub(crate) fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Returns the published shared connection without serializing callers.
    ///
    /// This is the hot path for shared-session creation; it only takes the read
    /// side of the slot lock.
    pub(crate) async fn current(&self) -> Option<Arc<MultiplexedConnection>> {
        self.slot.read().await.clone()
    }

    /// Advances the epoch and moves any cached connection into retirement.
    ///
    /// Bumping the epoch under the write lock fences every promotion that was
    /// captured earlier, so a slow negotiation cannot repopulate the slot after
    /// this returns.
    pub(crate) async fn stop_accepting_new_sessions(&self) {
        let mut slot = self.slot.write().await;
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Some(connection) = slot.take() {
            self.retain_retiring(connection);
        }
    }

    /// Removes the cached connection only if it is the one the caller observed.
    ///
    /// A different connection can already occupy the slot after a reconnect, so
    /// the pointer identity check avoids retiring a healthy replacement.
    pub(crate) async fn clear_if_same(&self, connection: &Arc<MultiplexedConnection>) {
        let mut slot = self.slot.write().await;
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, connection))
        {
            if let Some(connection) = slot.take() {
                self.retain_retiring(connection);
            }
        }
    }

    /// Publishes a promoted connection only while the cache is still current.
    ///
    /// The closed flag and `expected_generation` are checked while the write
    /// lock is held and before `upgrade` runs. When the fence rejects the
    /// publication, `upgrade` is never called and the candidate connection is
    /// dropped, so a late promotion cannot overwrite a close or a newer epoch.
    pub(crate) async fn publish_if_current<Upgrade>(
        &self,
        expected_generation: u64,
        upgrade: Upgrade,
    ) where
        Upgrade: FnOnce() -> Arc<MultiplexedConnection> + Send,
    {
        let mut slot = self.slot.write().await;
        if self.closed.load(Ordering::Acquire)
            || expected_generation != self.generation.load(Ordering::Acquire)
        {
            return;
        }
        *slot = Some(upgrade());
    }

    /// Joins every retiring connection until `deadline`, keeping only the live ones.
    ///
    /// Returns the first drain failure after attempting to join all connections.
    ///
    /// # Errors
    ///
    /// Returns a driver I/O error or task failure from a retiring connection.
    pub(crate) async fn retire_all_until(&self, deadline: RequestDeadline) -> anyhow::Result<()> {
        let retiring = self
            .retiring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut failure = None;
        for connection in retiring {
            if let Err(error) = connection.close_and_join(deadline).await {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        self.retiring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|connection| !connection.driver_finished());
        failure.map_or(Ok(()), Err)
    }

    /// Disables new sessions on a connection and tracks it until its driver ends.
    ///
    /// Finished connections are pruned first so the retiring list cannot grow
    /// without bound across repeated reconnects.
    fn retain_retiring(&self, connection: Arc<MultiplexedConnection>) {
        let mut retiring = self.retiring.lock().unwrap_or_else(PoisonError::into_inner);
        retiring.retain(|connection| !connection.driver_finished());
        connection.disable_new_sessions();
        retiring.push(connection);
    }

    #[cfg(test)]
    pub(crate) async fn store_for_test(&self, connection: Arc<MultiplexedConnection>) {
        *self.slot.write().await = Some(connection);
    }

    #[cfg(test)]
    pub(crate) fn retiring_is_empty_for_test(&self) -> bool {
        self.retiring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }
}

impl Drop for SharedConnectionCache {
    fn drop(&mut self) {
        if let Some(connection) = self.slot.get_mut().take() {
            connection.disable_new_sessions();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SharedConnectionCache;

    // The upgrade closure returns `Arc<MultiplexedConnection>`; a `panic!` body
    // coerces to that type and fails the test if the fence ever calls it.

    #[tokio::test]
    async fn closed_cache_rejects_publication_without_invoking_upgrade() {
        let cache = SharedConnectionCache::default();
        cache.mark_closed();
        cache
            .publish_if_current(cache.generation(), || {
                panic!("the upgrade closure must not run when the cache is closed")
            })
            .await;
        assert!(cache.current().await.is_none());
    }

    #[tokio::test]
    async fn stale_generation_rejects_publication_without_invoking_upgrade() {
        let cache = SharedConnectionCache::default();
        let captured = cache.generation();
        cache.stop_accepting_new_sessions().await;
        assert_ne!(captured, cache.generation());
        cache
            .publish_if_current(captured, || {
                panic!("the upgrade closure must not run for a stale generation")
            })
            .await;
        assert!(cache.current().await.is_none());
    }
}
