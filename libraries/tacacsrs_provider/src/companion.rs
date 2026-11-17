//! Provider-owned services with an explicit managed lifetime.

use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Read-only readiness and cancellation for a companion.
pub struct CompanionContext {
    /// Current readiness and subsequent changes.
    pub ready: watch::Receiver<bool>,
    /// The host cancels this token before cleanup.
    /// Cancelling this child token does not stop the host.
    pub cancellation: CancellationToken,
}

/// An inert service that the agent starts and joins.
///
/// Construction must not perform I/O, spawn tasks, or mutate external state.
/// An unexpected return is fatal. After cancellation, return only after cleanup.
/// The runtime can abort the service at its shutdown deadline.
#[async_trait]
pub trait Companion: Send + 'static {
    /// Returns a stable diagnostic name.
    fn name(&self) -> &'static str;

    /// Runs the service and completes cleanup after cancellation.
    ///
    /// # Errors
    /// Returns an operational or cleanup error.
    async fn run(self: Box<Self>, context: CompanionContext) -> anyhow::Result<()>;
}
