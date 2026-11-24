//! Application stop requests from components.

use std::sync::{Arc, Mutex, PoisonError};

use tokio_util::sync::CancellationToken;

use crate::ShutdownSignal;

/// Lets a component stop the application.
///
/// The host creates one value for each application run and gives clones to the
/// components. A stop request starts the same graceful shutdown as a process
/// stop signal. A stop with an error also makes the host return that error, so
/// the process exits with a failure status.
///
/// A stop request does not wait for shutdown. Hosted services still observe
/// shutdown through their [`ShutdownSignal`].
#[derive(Clone, Debug, Default)]
pub struct ApplicationLifetime {
    token: CancellationToken,
    error: Arc<Mutex<Option<anyhow::Error>>>,
}

impl ApplicationLifetime {
    /// Creates the lifetime of a new application run.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests a graceful stop with a successful result.
    ///
    /// Later calls have no effect.
    pub fn stop(&self) {
        self.token.cancel();
    }

    /// Requests a graceful stop with a failure result.
    ///
    /// The host keeps the first error. It ignores the errors of later calls.
    pub fn stop_with_error(&self, error: anyhow::Error) {
        let mut slot = self.error.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(error);
        }
        drop(slot);
        self.token.cancel();
    }

    /// Returns an observer of the stop request.
    #[must_use]
    pub fn stopping(&self) -> ShutdownSignal {
        ShutdownSignal::from(&self.token)
    }

    /// Returns `true` after a stop request.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Removes and returns the first stop error.
    ///
    /// The host calls this method after shutdown is complete.
    #[must_use]
    pub fn take_error(&self) -> Option<anyhow::Error> {
        self.error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_with_error_keeps_the_first_error() {
        let lifetime = ApplicationLifetime::new();
        let component = lifetime.clone();
        let stopping = lifetime.stopping();
        assert!(!lifetime.is_stopping());

        component.stop_with_error(anyhow::anyhow!("first"));
        component.stop_with_error(anyhow::anyhow!("second"));
        stopping.requested().await;

        assert!(lifetime.is_stopping());
        assert_eq!(
            lifetime
                .take_error()
                .map(|error| error.to_string())
                .as_deref(),
            Some("first")
        );
        assert!(lifetime.take_error().is_none());
    }

    #[test]
    fn stop_has_no_error() {
        let lifetime = ApplicationLifetime::new();
        lifetime.clone().stop();
        assert!(lifetime.is_stopping());
        assert!(lifetime.take_error().is_none());
    }
}
