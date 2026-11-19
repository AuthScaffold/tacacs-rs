//! Named background services that the host starts and joins.

use std::sync::Arc;

use async_trait::async_trait;

use crate::ShutdownSignal;

/// A background service that the host starts once and joins.
///
/// Construction must not perform I/O, spawn tasks, or change external state.
/// Keep mutable run state inside [`HostedService::run`]. When a health check
/// observes the service, inject one shared state value into both objects.
#[async_trait]
pub trait HostedService: Send + Sync + 'static {
    /// Returns a stable, secret-free diagnostic name.
    fn name(&self) -> &'static str;

    /// Runs the service until shutdown and then completes owned cleanup.
    ///
    /// The host treats a return before shutdown as fatal. At its shutdown
    /// deadline, the host can abort the service.
    ///
    /// # Errors
    /// Returns an operational or cleanup error.
    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()>;
}
