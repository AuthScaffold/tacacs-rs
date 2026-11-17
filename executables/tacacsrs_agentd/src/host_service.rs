//! Owned host services supervised alongside listeners and source observation.

use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use tacacsrs_agent::RuntimeHealthSnapshot;

pub(crate) struct HostContext {
    pub(crate) health: watch::Receiver<RuntimeHealthSnapshot>,
    pub(crate) cancellation: CancellationToken,
}

/// A critical host peer with cancellation and bounded, awaited cleanup.
#[async_trait]
pub(crate) trait HostService: Send + 'static {
    fn name(&self) -> &'static str;

    /// Runs until cancellation and finishes cleanup before returning.
    ///
    /// An early return is fatal. The host aborts work at its shared shutdown deadline.
    async fn run(self: Box<Self>, context: HostContext) -> anyhow::Result<()>;
}
