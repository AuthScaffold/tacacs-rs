//! Loopback TCP IPC listener.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, bail};
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgentServer;
use tokio_stream::wrappers::TcpListenerStream;

use crate::ipc::GrpcService;
use crate::routing::RoutingState;
use crate::runtime::shutdown_signal;

/// Serves loopback TCP IPC clients until shutdown is requested.
///
/// This path exists primarily for non-Unix development workflows where a Unix
/// domain socket is not available.
pub(crate) async fn serve(address: SocketAddr, state: Arc<RoutingState>) -> anyhow::Result<()> {
    if !address.ip().is_loopback() {
        log::error!("Refusing non-loopback TCP IPC endpoint: {address}");
        bail!("TCP IPC endpoint must be loopback-only: {address}");
    }

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to bind TCP IPC endpoint {address}"))?;
    let incoming = TcpListenerStream::new(listener);
    let grpc_service = GrpcService::new(Arc::clone(&state));

    log::info!("Listening for IPC clients on TCP {address}");

    tonic::transport::Server::builder()
        .add_service(TacacsAgentServer::new(grpc_service))
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await
        .with_context(|| format!("TCP IPC server {address} failed"))?;

    log::info!("Shutdown signal received; draining active IPC clients");
    state.wait_for_active_clients().await;
    Ok(())
}
