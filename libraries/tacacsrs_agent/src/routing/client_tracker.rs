//! Active IPC request tracking for graceful listener shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;

/// Tracks how many client handlers are currently executing so shutdown can stop
/// accepting new work first and then wait for in-flight requests to complete.
///
/// The tracker uses an atomic counter plus a [`Notify`] to avoid holding a lock
/// during the entire RPC handler lifetime. Incrementing and decrementing the
/// counter is lock-free; only the shutdown waiter blocks on the notification.
#[derive(Default)]
pub(super) struct ClientTracker {
    /// Number of IPC handlers currently executing a request.
    active_clients: AtomicUsize,
    /// Notification signalled when `active_clients` reaches zero.
    drained: Notify,
}

/// RAII guard that decrements the active-client count on drop.
///
/// Created by [`ClientTracker::start_guard`] and held for the duration of one
/// IPC request handler. When the last guard drops, the tracker notifies the
/// shutdown waiter.
pub(crate) struct ClientGuard {
    tracker: Arc<ClientTracker>,
}

impl ClientTracker {
    /// Registers one active client handler and returns a guard that will
    /// decrement the count automatically when the handler finishes.
    pub(super) fn start_guard(self: &Arc<Self>) -> ClientGuard {
        self.active_clients.fetch_add(1, Ordering::Relaxed);
        ClientGuard {
            tracker: Arc::clone(self),
        }
    }

    /// Waits until all client handlers tracked by this instance have dropped
    /// their guards.
    ///
    /// This is used only during shutdown after the listeners have stopped
    /// accepting new connections, so the count is expected to trend toward
    /// zero. The loop handles races where a notification arrives just before a
    /// waiter starts sleeping.
    pub(super) async fn wait_for_zero(&self) {
        loop {
            if self.active_clients.load(Ordering::Relaxed) == 0 {
                log::debug!("All in-flight IPC client handlers have drained");
                return;
            }

            // Register for notification before the recheck so a
            // decrement-to-zero racing between the recheck and the await is
            // captured by the already-registered future.
            let notified = self.drained.notified();

            let active_clients = self.active_clients.load(Ordering::Relaxed);
            if active_clients == 0 {
                log::debug!("All in-flight IPC client handlers have drained");
                return;
            }

            log::debug!("Waiting for {active_clients} in-flight IPC client handler(s) to finish");
            notified.await;
        }
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        if self.tracker.active_clients.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.tracker.drained.notify_waiters();
        }
    }
}
