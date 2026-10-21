//! Narrow injection point for host-composed runtime listener services.

use async_trait::async_trait;

use super::{RuntimeHealthPublisher, ShutdownReceiver};

/// A long-lived listener service driven by the agent runtime.
///
/// The agent runtime owns the shutdown signal, the drain deadline, and the join.
/// A host composes a listener, for example the local client API over IPC, and
/// injects it through [`TacacsClientService::serve_until`]. The injected service
/// receives the runtime shutdown subscription and the health publisher so it can
/// report its own listener state. The raw TACACS+ proxy remains an internal
/// runtime listener and is not injected.
///
/// [`TacacsClientService::serve_until`]: crate::TacacsClientService::serve_until
#[async_trait]
pub trait RuntimeListenerService: Send + Sync + 'static {
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
