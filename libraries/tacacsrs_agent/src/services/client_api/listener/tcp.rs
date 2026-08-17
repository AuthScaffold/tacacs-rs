//! Loopback TCP IPC listener for non-Unix builds.

use std::net::SocketAddr;

use anyhow::{Context, bail};
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgentServer;
use tokio::sync::watch;
use tokio_stream::wrappers::TcpListenerStream;

use crate::runtime::{ListenerRegistration, RuntimeHealthSnapshot, ShutdownReceiver};
use crate::services::client_api::health::StandardHealth;
use crate::services::client_api::ClientApiService;

/// Runs a loopback TCP IPC listener until shutdown starts.
///
/// This listener supports non-Unix development, where a Unix domain socket is
/// not available.
pub(crate) async fn serve(
    address: SocketAddr,
    service: ClientApiService,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
    health: watch::Receiver<RuntimeHealthSnapshot>,
) -> anyhow::Result<()> {
    if !address.ip().is_loopback() {
        log::error!("The TCP IPC endpoint is not a loopback address: {address}");
        bail!("TCP IPC endpoint must be loopback-only: {address}");
    }

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to bind TCP IPC endpoint {address}"))?;
    let incoming = TcpListenerStream::new(listener);
    let (standard_health, health_service) = StandardHealth::new(health).await;
    let health_task = tokio::spawn(standard_health.run(shutdown.clone()));
    registration.mark_bound();

    log::info!("The IPC listener accepts clients on TCP {address}");

    tonic::transport::Server::builder()
        .add_service(TacacsAgentServer::new(service.grpc_service()))
        .add_service(health_service)
        .serve_with_incoming_shutdown(incoming, shutdown.wait())
        .await
        .with_context(|| format!("TCP IPC server {address} failed"))?;

    log::info!("Received a shutdown signal; draining active IPC requests");
    service.wait_for_active_requests().await;
    health_task
        .await
        .context("Standard gRPC health bridge failed")?;
    Ok(())
}
