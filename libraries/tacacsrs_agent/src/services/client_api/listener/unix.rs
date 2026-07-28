//! Unix domain socket IPC listener.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgentServer;
use tokio::sync::watch;
use tokio_stream::wrappers::UnixListenerStream;

use crate::runtime::{ListenerRegistration, RuntimeHealthSnapshot, ShutdownReceiver};
use crate::services::client_api::health::StandardHealth;
use crate::services::client_api::ClientApiService;

/// Serves Unix domain socket IPC clients until shutdown is requested.
///
/// The gRPC server stops accepting new requests once shutdown is signalled,
/// waits for active RPC handlers to drain, and then removes the socket path.
pub(crate) async fn serve(
    path: &Path,
    service: ClientApiService,
    socket_mode: u32,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
    health: watch::Receiver<RuntimeHealthSnapshot>,
) -> anyhow::Result<()> {
    let listener = prepare_unix_listener(path, socket_mode).await?;
    let socket_guard = UnixSocketCleanupGuard::new(path);
    let incoming = UnixListenerStream::new(listener);
    let (standard_health, health_service) = StandardHealth::new(health).await;
    let health_task = tokio::spawn(standard_health.run(shutdown.clone()));
    registration.mark_bound();

    log::info!("Listening for IPC clients on Unix socket {}", path.display());

    tonic::transport::Server::builder()
        .add_service(TacacsAgentServer::new(service.grpc_service()))
        .add_service(health_service)
        .serve_with_incoming_shutdown(incoming, shutdown.wait())
        .await
        .with_context(|| format!("Unix IPC server {} failed", path.display()))?;

    log::info!("Shutdown signal received; draining active IPC clients");
    service.wait_for_active_requests().await;
    health_task
        .await
        .context("Standard gRPC health bridge failed")?;
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::prepare_unix_listener;

    fn test_socket_path(socket_name: &str) -> PathBuf {
        let unique = format!(
            "{}-{}-{}.sock",
            socket_name,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after Unix epoch")
                .as_nanos()
        );
        PathBuf::from("/tmp").join(unique)
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real Unix socket + filesystem I/O
    async fn prepare_unix_listener_rejects_active_socket_path() {
        let path = test_socket_path("tacacs-listener-existing-socket");
        let existing_listener = tokio::net::UnixListener::bind(&path).unwrap();

        let error = prepare_unix_listener(&path, 0o660).await.unwrap_err();

        assert!(error.to_string().contains("already accepting connections"));
        drop(existing_listener);
        let _ = tokio::fs::remove_file(path).await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real Unix socket + filesystem I/O
    async fn prepare_unix_listener_replaces_stale_socket_path() {
        let path = test_socket_path("tacacs-listener-stale-socket");
        let stale_listener = tokio::net::UnixListener::bind(&path).unwrap();
        drop(stale_listener);

        let listener = prepare_unix_listener(&path, 0o660).await.unwrap();
        drop(listener);

        assert!(tokio::fs::try_exists(&path).await.unwrap());
        let _ = tokio::fs::remove_file(path).await;
    }
}
