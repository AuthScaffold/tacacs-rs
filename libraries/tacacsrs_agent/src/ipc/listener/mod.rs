//! Local IPC listener transports.

use std::sync::Arc;

use tacacsrs_agent_client::IpcEndpoint;

use crate::routing::RoutingState;

mod tcp;
#[cfg(unix)]
mod unix;

#[cfg(unix)]
/// Serves the configured local IPC endpoint until process shutdown is signalled.
pub(crate) async fn serve(
    endpoint: &IpcEndpoint,
    state: Arc<RoutingState>,
    socket_mode: u32,
) -> anyhow::Result<()> {
    match endpoint {
        IpcEndpoint::Unix(path) => unix::serve(path, state, socket_mode).await,
        IpcEndpoint::Tcp(address) => tcp::serve(*address, state).await,
    }
}

#[cfg(not(unix))]
/// Serves the configured local IPC endpoint until process shutdown is signalled.
pub(crate) async fn serve(endpoint: &IpcEndpoint, state: Arc<RoutingState>) -> anyhow::Result<()> {
    match endpoint {
        IpcEndpoint::Tcp(address) => tcp::serve(*address, state).await,
    }
}

#[cfg(all(test, unix))]
pub(crate) use unix::prepare_unix_listener;
