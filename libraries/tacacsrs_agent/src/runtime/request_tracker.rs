//! Active request tracking for graceful listener shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;

/// Tracks how many request handlers are currently executing so shutdown can stop
/// accepting new work first and then wait for in-flight requests to complete.
///
/// The tracker uses an atomic counter plus a [`Notify`] to avoid holding a lock
/// during the entire RPC handler lifetime. Incrementing and decrementing the
/// counter is lock-free; only the shutdown waiter blocks on the notification.
#[derive(Default)]
pub(crate) struct RequestTracker {
    /// Number of handlers currently executing a request.
    active_requests: AtomicUsize,
    /// Notification signalled when `active_requests` reaches zero.
    drained: Notify,
}

/// RAII guard that decrements the active-client count on drop.
///
/// Created by [`RequestTracker::start_request`] and held for the duration of one
/// request handler. When the last guard drops, the tracker notifies the shutdown
/// waiter.
pub(crate) struct RequestGuard {
    tracker: Arc<RequestTracker>,
}

impl RequestTracker {
    /// Registers one active client handler and returns a guard that will
    /// decrement the count automatically when the handler finishes.
    pub(crate) fn start_request(self: &Arc<Self>) -> RequestGuard {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        RequestGuard {
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
    pub(crate) async fn wait_for_active_requests(&self) {
        loop {
            if self.active_requests.load(Ordering::Relaxed) == 0 {
                log::debug!("All in-flight request handlers have drained");
                return;
            }

            // Register for notification before the recheck so a
            // decrement-to-zero racing between the recheck and the await is
            // captured by the already-registered future.
            let notified = self.drained.notified();

            let active_requests = self.active_requests.load(Ordering::Relaxed);
            if active_requests == 0 {
                log::debug!("All in-flight request handlers have drained");
                return;
            }

            log::debug!("Waiting for {active_requests} in-flight request handler(s) to finish");
            notified.await;
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.tracker.active_requests.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.tracker.drained.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::RequestTracker;

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio time not supported
    async fn test_drain_returns_immediately_with_no_active_requests() {
        let tracker = Arc::new(RequestTracker::default());

        tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
            .await
            .expect("wait_for_active_requests should return immediately with no active requests");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
    async fn test_drain_waits_for_in_flight_request_then_completes() {
        let tracker = Arc::new(RequestTracker::default());
        let request_guard = tracker.start_request();

        let drain_result =
            tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
                .await;
        assert!(
            drain_result.is_err(),
            "wait_for_active_requests should block while a request is in flight"
        );

        drop(request_guard);

        tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
            .await
            .expect("wait_for_active_requests should complete after all requests finish");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio time not supported
    async fn test_drain_completes_when_guard_drops_between_check_and_await() {
        let tracker = Arc::new(RequestTracker::default());
        let request_guard = tracker.start_request();
        drop(request_guard);

        tokio::time::timeout(Duration::from_millis(200), tracker.wait_for_active_requests())
            .await
            .expect("wait_for_active_requests must not hang after a racing guard drop");
    }
}
