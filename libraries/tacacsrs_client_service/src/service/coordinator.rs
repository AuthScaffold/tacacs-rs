use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};

use super::config::{IpcEndpoint, ServiceConfig};
use super::state::ServiceState;
use crate::upstream::{NetworkUpstreamConnector, UpstreamConnector};

/// Long-lived local TACACS+ client service.
pub struct TacacsClientService {
    config: ServiceConfig,
    state: Arc<ServiceState>,
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
            config.preferred_probe_interval,
        ));

        Ok(Self { config, state })
    }

    /// Starts serving local IPC requests until the process is terminated.
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
