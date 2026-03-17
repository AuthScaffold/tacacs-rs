//! Listener orchestration for the central TACACS+ client service.
//!
//! This module owns process-level behavior: startup validation, IPC listener
//! creation, graceful shutdown, and delegation into [`super::state::ServiceState`]
//! for per-client request handling and upstream failover decisions.

use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};

use super::config::{IpcEndpoint, ServiceConfig};
use super::state::ServiceState;
use crate::upstream::{NetworkUpstreamConnector, UpstreamConnector};

/// Long-lived local TACACS+ client service.
///
/// [`TacacsClientService`] is the bridge between operator-facing configuration
/// and the shared runtime state used by all accepted IPC clients.
pub struct TacacsClientService {
    config: ServiceConfig,
    state: Arc<ServiceState>,
}

/// Returns the short retry cooldown used after a failed upstream connect or a
/// request-time connection failure.
///
/// Upstream addresses are commonly VIPs or software load balancers, so the
/// reconnect backoff should be much shorter than the preferred-server probe
/// interval. We still cap it to the upstream connect timeout so a caller that
/// already chose an aggressive timeout does not get a longer retry penalty.
fn connect_retry_cooldown(connect_timeout: Duration) -> Duration {
    connect_timeout.min(Duration::from_millis(250))
}

impl TacacsClientService {
    /// Builds a TACACS+ client service with persistent upstream connections and
    /// ordered failover state.
    ///
    /// # Errors
    ///
    /// Returns an error if no upstream TACACS+ servers are configured.
    pub fn new(config: ServiceConfig) -> anyhow::Result<Self> {
        if config.server_addresses.is_empty() {
            bail!("At least one TACACS+ server address must be configured");
        }

        let connector: Arc<dyn UpstreamConnector> =
            Arc::new(NetworkUpstreamConnector::new(config.upstream.clone()));
        let state = Arc::new(ServiceState::new(
            config.server_addresses.clone(),
            connector,
            connect_retry_cooldown(config.upstream.connect_timeout),
            config.preferred_probe_interval,
        ));

        Ok(Self { config, state })
    }

    #[cfg(test)]
    pub(super) fn new_with_connector(
        config: ServiceConfig,
        connector: Arc<dyn UpstreamConnector>,
    ) -> anyhow::Result<Self> {
        if config.server_addresses.is_empty() {
            bail!("At least one TACACS+ server address must be configured");
        }

        let state = Arc::new(ServiceState::new(
            config.server_addresses.clone(),
            connector,
            connect_retry_cooldown(config.upstream.connect_timeout),
            config.preferred_probe_interval,
        ));

        Ok(Self { config, state })
    }

    /// Starts serving local IPC requests until the process is terminated.
    ///
    /// Startup first performs a best-effort warm-up of the first responsive
    /// upstream server and, when multiple servers are configured, launches the
    /// background probe that returns new sessions to the preferred server after
    /// recovery.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPC listener cannot be created or if the local
    /// endpoint configuration is invalid for the current platform.
    pub async fn serve(self) -> anyhow::Result<()> {
        self.state.warm_connections().await;
        let probe_task =
            (self.state.server_count() > 1).then(|| self.state.spawn_preferred_probe());

        let result = match &self.config.endpoint {
            #[cfg(unix)]
            IpcEndpoint::Unix(path) => self.serve_unix(path).await,
            IpcEndpoint::Tcp(address) => self.serve_tcp(*address).await,
        };

        if let Some(task) = probe_task {
            task.abort();
        }

        result
    }

    #[cfg(unix)]
    /// Serves Unix domain socket IPC clients until shutdown is requested.
    ///
    /// After shutdown is signalled the listener stops accepting new clients,
    /// waits for active handlers to drain, and then removes the socket path.
    async fn serve_unix(&self, path: &PathBuf) -> anyhow::Result<()> {
        let listener = self.prepare_unix_listener(path).await?;

        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accept_result = listener.accept() => {
                    let (stream, _) = accept_result.context("Failed to accept Unix socket connection")?;
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        if let Err(error) = state.handle_client(stream).await {
                            log::error!("IPC client handling failed: {error}");
                        }
                    });
                }
            }
        }

        self.state.wait_for_active_clients().await;
        tokio::fs::remove_file(path)
            .await
            .with_context(|| format!("Failed to remove socket {}", path.display()))?;
        Ok(())
    }

    #[cfg(unix)]
    /// Creates the Unix listener, safely handling either a live competing
    /// service instance or a stale filesystem entry from a previous run.
    pub(super) async fn prepare_unix_listener(
        &self,
        path: &PathBuf,
    ) -> anyhow::Result<tokio::net::UnixListener> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create socket directory {}", parent.display())
            })?;
        }

        if tokio::fs::try_exists(path)
            .await
            .with_context(|| format!("Failed to inspect socket path {}", path.display()))?
        {
            match tokio::net::UnixStream::connect(path).await {
                Ok(_) => bail!(
                    "Unix socket {} is already accepting connections; another service instance may already be running",
                    path.display()
                ),
                Err(_) => {
                    tokio::fs::remove_file(path).await.with_context(|| {
                        format!("Failed to remove stale socket {}", path.display())
                    })?;
                }
            }
        }

        let listener = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("Failed to bind Unix socket {}", path.display()))?;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(self.config.socket_mode))
            .with_context(|| format!("Failed to set permissions on socket {}", path.display()))?;
        Ok(listener)
    }

    /// Serves loopback TCP IPC clients until shutdown is requested.
    ///
    /// This path exists primarily for non-Unix development workflows where a
    /// Unix domain socket is not available.
    async fn serve_tcp(&self, address: SocketAddr) -> anyhow::Result<()> {
        if !address.ip().is_loopback() {
            bail!("TCP IPC endpoint must be loopback-only: {address}");
        }

        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("Failed to bind TCP IPC endpoint {address}"))?;

        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accept_result = listener.accept() => {
                    let (stream, _) = accept_result.context("Failed to accept TCP IPC connection")?;
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        if let Err(error) = state.handle_client(stream).await {
                            log::error!("IPC client handling failed: {error}");
                        }
                    });
                }
            }
        }

        self.state.wait_for_active_clients().await;
        Ok(())
    }
}

/// Waits for a process termination signal that should stop the service from
/// accepting new IPC clients.
///
/// Unix builds listen for both `SIGTERM` and Ctrl-C. Other platforms fall back
/// to Ctrl-C only.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut terminate_signal) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate_signal.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
