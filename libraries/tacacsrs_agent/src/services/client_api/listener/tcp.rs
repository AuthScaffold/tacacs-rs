//! Loopback TCP IPC listener for non-Unix builds.

use std::net::SocketAddr;

use anyhow::{Context, bail};
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgentServer;
use tokio_stream::wrappers::TcpListenerStream;

use crate::runtime::{ListenerRegistration, ShutdownReceiver};
use crate::services::client_api::ClientApiService;

/// Serves loopback TCP IPC clients until shutdown is requested.
///
/// This path exists primarily for non-Unix development workflows where a Unix
/// domain socket is not available.
pub(crate) async fn serve(
    address: SocketAddr,
    service: ClientApiService,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
) -> anyhow::Result<()> {
    if !address.ip().is_loopback() {
        log::error!("Refusing non-loopback TCP IPC endpoint: {address}");
        bail!("TCP IPC endpoint must be loopback-only: {address}");
    }

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to bind TCP IPC endpoint {address}"))?;
    let incoming = TcpListenerStream::new(listener);
    registration.mark_bound();

    log::info!("Listening for IPC clients on TCP {address}");

    tonic::transport::Server::builder()
        .add_service(TacacsAgentServer::new(service.grpc_service()))
        .serve_with_incoming_shutdown(incoming, shutdown.wait())
        .await
        .with_context(|| format!("TCP IPC server {address} failed"))?;

    log::info!("Shutdown signal received; draining active IPC clients");
    service.wait_for_active_requests().await;
    Ok(())
}
