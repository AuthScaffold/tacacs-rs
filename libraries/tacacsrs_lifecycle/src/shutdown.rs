//! Application shutdown request and observation.

use std::future::Future;

use tokio_util::sync::CancellationToken;

/// Requests application shutdown.
///
/// Only the host owns this value. Components receive a [`ShutdownSignal`].
#[derive(Debug, Default)]
pub struct ShutdownRequester {
    token: CancellationToken,
}

impl ShutdownRequester {
    /// Creates a requester for a new application run.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns an observer of this requester.
    #[must_use]
    pub fn signal(&self) -> ShutdownSignal {
        ShutdownSignal::from(&self.token)
    }

    /// Requests shutdown. Later calls have no effect.
    pub fn request(&self) {
        self.token.cancel();
    }

    /// Returns `true` after a shutdown request.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.token.is_cancelled()
    }
}

/// Observes an application shutdown request.
///
/// A signal cannot request shutdown. Clones observe the same request.
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    token: CancellationToken,
}

impl ShutdownSignal {
    /// Completes when the host requests shutdown.
    pub async fn requested(&self) {
        self.token.cancelled().await;
    }

    /// Returns an owned future that completes when the host requests shutdown.
    pub fn requested_owned(self) -> impl Future<Output = ()> + Send + 'static {
        self.token.cancelled_owned()
    }

    /// Returns `true` after the host requests shutdown.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.token.is_cancelled()
    }
}

impl From<&CancellationToken> for ShutdownSignal {
    /// Observes `token` through a child token, so the signal cannot cancel `token`.
    fn from(token: &CancellationToken) -> Self {
        Self {
            token: token.child_token(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signal_observes_request_and_cannot_request_shutdown() {
        let requester = ShutdownRequester::new();
        let signal = requester.signal();
        let owned = signal.clone().requested_owned();
        assert!(!signal.is_requested());
        requester.request();
        signal.requested().await;
        owned.await;
        assert!(requester.signal().is_requested());

        let token = CancellationToken::new();
        drop(ShutdownSignal::from(&token));
        assert!(!token.is_cancelled());
    }
}
