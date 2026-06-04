//! Unix domain socket IPC listener.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgentServer;
use tokio_stream::wrappers::UnixListenerStream;

use crate::ipc::GrpcService;
use crate::routing::RoutingState;
use crate::runtime::shutdown_signal;

/// Serves Unix domain socket IPC clients until shutdown is requested.
///
/// The gRPC server stops accepting new requests once shutdown is signalled,
/// waits for active RPC handlers to drain, and then removes the socket path.
pub(crate) async fn serve(
    path: &Path,
    state: Arc<RoutingState>,
    socket_mode: u32,
) -> anyhow::Result<()> {
    let listener = prepare_unix_listener(path, socket_mode).await?;
    let incoming = UnixListenerStream::new(listener);
    let grpc_service = GrpcService::new(Arc::clone(&state));

    log::info!("Listening for IPC clients on Unix socket {}", path.display());

    tonic::transport::Server::builder()
        .add_service(TacacsAgentServer::new(grpc_service))
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await
        .with_context(|| format!("Unix IPC server {} failed", path.display()))?;

    log::info!("Shutdown signal received; draining active IPC clients");
    state.wait_for_active_clients().await;
    match tokio::fs::remove_file(path).await {
        Ok(()) => {
            log::debug!("Removed Unix socket {}", path.display());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            log::debug!("Unix socket {} was already removed during shutdown", path.display());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to remove socket {}", path.display()));
        }
    }
    Ok(())
}

/// Creates the Unix listener, safely handling either a live competing service
/// instance or a stale filesystem entry from a previous run.
pub(crate) async fn prepare_unix_listener(
    path: &Path,
    socket_mode: u32,
) -> anyhow::Result<tokio::net::UnixListener> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create socket directory {}", parent.display()))?;
    }

    if tokio::fs::try_exists(path)
        .await
        .with_context(|| format!("Failed to inspect socket path {}", path.display()))?
    {
        log::debug!("Socket path {} already exists; checking if it is active", path.display());
        match tokio::net::UnixStream::connect(path).await {
            Ok(_) => {
                log::error!(
                    "Unix socket {} is already accepting connections; refusing to start",
                    path.display()
                );
                bail!(
                    "Unix socket {} is already accepting connections; another service instance may already be running",
                    path.display()
                );
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                log::info!(
                    "Removing stale Unix socket {} (previous instance likely crashed)",
                    path.display()
                );
                tokio::fs::remove_file(path)
                    .await
                    .with_context(|| format!("Failed to remove stale socket {}", path.display()))?;
            }
            Err(error) => {
                log::error!(
                    "Cannot determine state of existing socket {}: {error}",
                    path.display()
                );
                return Err(error).with_context(|| {
                    format!(
                        "Refusing to remove existing socket {} because it may still belong to another service instance",
                        path.display()
                    )
                });
            }
        }
    }

    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("Failed to bind Unix socket {}", path.display()))?;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode))
        .await
        .with_context(|| format!("Failed to set permissions on socket {}", path.display()))?;
    Ok(listener)
}
