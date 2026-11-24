//! Narrow injection point for host-composed runtime listener services.

use async_trait::async_trait;

use super::{RuntimeHealthPublisher, RuntimeService, ShutdownReceiver};

/// A long-lived listener service driven by the agent runtime.
///
/// The agent runtime owns the shutdown signal, the drain deadline, and the join.
/// A host composes each listener, for example the local client API over IPC
/// and the raw TACACS+ proxy, and injects it through
/// [`TacacsClientService::serve_until`]. The injected service receives the
/// runtime shutdown subscription and the health publisher so it can report its
/// own listener state.
///
/// A listener that returns `Ok(())` before shutdown is complete. The runtime
/// logs the return and continues. A listener that returns an error or panics
/// stops the runtime.
///
/// [`TacacsClientService::serve_until`]: crate::TacacsClientService::serve_until
#[async_trait]
pub trait RuntimeListenerService: Send + Sync + 'static {
    /// Returns a stable, secret-free name for logs.
    fn name(&self) -> &'static str;

    /// Returns the runtime service whose listener state this listener
    /// reports, or `None` for a listener outside runtime readiness.
    ///
    /// The host requires one selected listener for each enabled runtime
    /// service.
    fn service(&self) -> Option<RuntimeService> {
        None
    }

    /// Serves until the shutdown signal fires, then drains and returns.
    ///
    /// # Errors
    /// Returns a bind, serve, or cleanup error after the listener drains.
    async fn serve(
        self: Box<Self>,
        shutdown: ShutdownReceiver,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()>;
}
