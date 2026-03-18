//! Listener orchestration for the central TACACS+ client service.
//!
//! This module owns process-level behavior: startup validation, IPC listener
//! creation, graceful shutdown, and delegation into [`super::state::ServiceState`]
//! for per-client request handling and upstream failover decisions.
//!
//! # Startup sequence
//!
//! 1. [`TacacsClientService::new`] validates configuration (≥1 server, etc.).
//! 2. [`TacacsClientService::serve`] warms upstream connections, optionally
//!    spawns the preferred-server probe, and binds the IPC listener.
//! 3. The gRPC server accepts clients until a shutdown signal is received.
//!
//! # Graceful shutdown
//!
//! Shutdown is cooperative:
//!
//! 1. The listener stops accepting new connections (signal handler fires).
//! 2. In-flight RPC handlers run to completion.
//! 3. The Unix socket path is removed (Unix only).

use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use tacacsrs_agent_client::ipc;
use tacacsrs_agent_client::ipc::tacacs_agent_server::{TacacsAgent, TacacsAgentServer};
use tacacsrs_agent_client::{AccountingOperation, IpcEndpoint};
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

use super::config::ServiceConfig;
use super::state::ServiceState;
use crate::upstream::{NetworkUpstreamConnector, UpstreamConnector};

/// Long-lived local TACACS+ client service.
///
/// [`TacacsClientService`] is the bridge between operator-facing configuration
/// and the shared runtime state used by all accepted IPC clients. Construction
/// validates the configuration and creates the internal failover state machine;
/// calling [`serve`](TacacsClientService::serve) starts the IPC listener.
///
/// The type is not `Clone` because it owns the listener lifecycle. Use
/// [`ServiceConfig`] to share configuration before constructing the service.
///
/// # Service lifecycle
///
/// ```text
/// [start]
///    |
///    v
/// Configuring ──> Validating ──> WarmingUp ──> Serving
///                                                 |
///                                          shutdown signal
///                                                 |
///                                                 v
///                                              Draining ──> Cleanup ──> [end]
/// ```
pub struct TacacsClientService {
    /// Validated operator configuration snapshot.
    config: ServiceConfig,
    /// Shared failover state used by all IPC client handlers.
    state: Arc<ServiceState>,
}

/// Thin gRPC service adapter that delegates every RPC into the shared
/// [`ServiceState`].
///
/// Each [`tonic`] handler creates a fresh instance of this adapter (it's
/// `Clone`), registers itself as an active client, and forwards the decoded
/// request into the state machine.
#[derive(Clone)]
struct GrpcService {
    state: Arc<ServiceState>,
}

#[tonic::async_trait]
impl TacacsAgent for GrpcService {
    /// Handles one unary accounting RPC from a local IPC client.
    ///
    /// Decodes the protobuf request, delegates to [`ServiceState`] for server
    /// selection and upstream execution, and encodes the result into the oneof
    /// `AccountingReply` envelope. Transport-level gRPC errors (e.g. invalid
    /// argument) are returned as [`Status`]; application-level errors (e.g.
    /// upstream failure) are returned inside the `ServiceError` variant of the
    /// reply.
    async fn accounting(
        &self,
        request: Request<ipc::AccountingRequest>,
    ) -> Result<Response<ipc::AccountingReply>, Status> {
        let request = AccountingOperation::try_from(request.into_inner())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let result = match self.state.execute_accounting_request(request).await {
            Ok(response) => ipc::AccountingReply {
                result: Some(ipc::accounting_reply::Result::Response(response.into_proto())),
            },
            Err(error) => ipc::AccountingReply {
                result: Some(ipc::accounting_reply::Result::Error(error.into_proto())),
            },
        };
        Ok(Response::new(result))
    }
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
    /// The gRPC server stops accepting new requests once shutdown is signalled,
    /// waits for active RPC handlers to drain, and then removes the socket path.
    async fn serve_unix(&self, path: &PathBuf) -> anyhow::Result<()> {
        let listener = self.prepare_unix_listener(path).await?;
        let incoming = UnixListenerStream::new(listener);
        let grpc_service = GrpcService {
            state: Arc::clone(&self.state),
        };

        tonic::transport::Server::builder()
            .add_service(TacacsAgentServer::new(grpc_service))
            .serve_with_incoming_shutdown(incoming, shutdown_signal())
            .await
            .with_context(|| format!("Unix IPC server {} failed", path.display()))?;

        self.state.wait_for_active_clients().await;
        match tokio::fs::remove_file(path).await {
            Ok(()) => {}
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
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::NotFound
                    ) =>
                {
                    tokio::fs::remove_file(path).await.with_context(|| {
                        format!("Failed to remove stale socket {}", path.display())
                    })?;
                }
                Err(error) => {
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

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(self.config.socket_mode))
            .await
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
        let incoming = TcpListenerStream::new(listener);
        let grpc_service = GrpcService {
            state: Arc::clone(&self.state),
        };

        tonic::transport::Server::builder()
            .add_service(TacacsAgentServer::new(grpc_service))
            .serve_with_incoming_shutdown(incoming, shutdown_signal())
            .await
            .with_context(|| format!("TCP IPC server {address} failed"))?;

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
