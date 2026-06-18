//! Unix domain socket IPC listener.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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
    let socket_guard = UnixSocketCleanupGuard::new(path);
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
    socket_guard.cleanup("Unix socket").await?;
    Ok(())
}

pub(crate) struct UnixSocketCleanupGuard {
    path: PathBuf,
    should_cleanup: bool,
}

impl UnixSocketCleanupGuard {
    #[must_use]
    pub(crate) fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            should_cleanup: true,
        }
    }

    pub(crate) async fn cleanup(mut self, label: &str) -> anyhow::Result<()> {
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => {
                log::debug!("Removed {label} {}", self.path.display());
                self.disarm();
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                log::debug!("{label} {} was already removed during shutdown", self.path.display());
                self.disarm();
                Ok(())
            }
            Err(error) => Err(error)
                .with_context(|| format!("Failed to remove {label} {}", self.path.display())),
        }
    }

    fn disarm(&mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for UnixSocketCleanupGuard {
    fn drop(&mut self) {
        if !self.should_cleanup {
            return;
        }

        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                log::debug!("Removed Unix socket {} during cancellation", self.path.display());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                log::debug!(
                    "Unix socket {} was already removed during cancellation",
                    self.path.display()
                );
            }
            Err(error) => {
                log::warn!(
                    "Failed to remove Unix socket {} during cancellation: {error}",
                    self.path.display()
                );
            }
        }
    }
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
    let mut socket_guard = UnixSocketCleanupGuard::new(path);

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode))
        .with_context(|| format!("Failed to set permissions on socket {}", path.display()))?;
    socket_guard.disarm();
    Ok(listener)
}
