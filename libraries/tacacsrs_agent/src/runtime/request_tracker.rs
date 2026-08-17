//! Active request tracking for graceful listener shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;

/// Tracks active request handlers for graceful shutdown.
///
/// The tracker uses an atomic counter and a [`Notify`]. It does not hold a lock
/// during the RPC handler lifetime. Only the shutdown task waits for a
/// notification.
#[derive(Default)]
pub(crate) struct RequestTracker {
    /// Number of active request handlers.
    active_requests: AtomicUsize,
    /// Notification sent when `active_requests` reaches zero.
    drained: Notify,
}

/// RAII guard that decreases the active-request count when dropped.
///
/// [`RequestTracker::start_request`] creates this guard for one request handler.
/// The last guard notifies the shutdown task when it drops.
pub(crate) struct RequestGuard {
    tracker: Arc<RequestTracker>,
}

impl RequestTracker {
    /// Registers one active request handler and returns its guard.
    pub(crate) fn start_request(self: &Arc<Self>) -> RequestGuard {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        RequestGuard {
            tracker: Arc::clone(self),
        }
    }

    /// Waits until all tracked request handlers drop their guards.
    ///
    /// Shutdown calls this method after the listeners stop accepting
    /// connections. The loop handles a notification that arrives before the
    /// task starts to wait.
    pub(crate) async fn wait_for_active_requests(&self) {
        loop {
            if self.active_requests.load(Ordering::Relaxed) == 0 {
                log::debug!("All active request handlers have finished");
                return;
            }

            // Register before reading the count again. This order captures a zero
            // transition that occurs before the task starts to wait.
            let notified = self.drained.notified();

            let active_requests = self.active_requests.load(Ordering::Relaxed);
            if active_requests == 0 {
                log::debug!("All active request handlers have finished");
                return;
            }

            log::debug!("Waiting for {active_requests} active request handler(s) to finish");
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
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio time.
    async fn test_drain_returns_immediately_with_no_active_requests() {
        let tracker = Arc::new(RequestTracker::default());

        tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
            .await
            .expect("wait_for_active_requests must return when no requests are active");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn test_drain_waits_for_in_flight_request_then_completes() {
        let tracker = Arc::new(RequestTracker::default());
        let request_guard = tracker.start_request();

        let drain_result =
            tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
                .await;
        assert!(
            drain_result.is_err(),
            "wait_for_active_requests must wait while a request is active"
        );

        drop(request_guard);

        tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
            .await
            .expect("wait_for_active_requests must finish after all requests finish");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio time.
    async fn test_drain_completes_when_guard_drops_between_check_and_await() {
        let tracker = Arc::new(RequestTracker::default());
        let request_guard = tracker.start_request();
        drop(request_guard);

        tokio::time::timeout(Duration::from_millis(200), tracker.wait_for_active_requests())
            .await
            .expect("wait_for_active_requests must finish after the guard drops");
    }
}
