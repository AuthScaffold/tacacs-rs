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
use tacacsrs_agent_client::{
    AccountingOperation, AuthorizationOperation, AuthorizationOperationResponse,
    AuthorizationResponseStatus, IpcEndpoint,
};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt, TacacsPlusServerType};
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
        let request = AccountingOperation::try_from(request.into_inner()).map_err(|error| {
            log::warn!("Invalid IPC accounting request: {error}");
            Status::invalid_argument(error.to_string())
        })?;
        log::debug!(
            "Received IPC accounting request: user={}, cmd={}",
            request.user,
            request.command,
        );
        let result = match self.state.execute_accounting_request(request).await {
            Ok(response) => {
                log::debug!(
                    "IPC accounting request completed: server={}, status={:?}",
                    response.server,
                    response.status,
                );
                ipc::AccountingReply {
                    result: Some(ipc::accounting_reply::Result::Response(response.into_proto())),
                }
            }
            Err(error) => {
                log::warn!("IPC accounting request failed: {error:?}");
                ipc::AccountingReply {
                    result: Some(ipc::accounting_reply::Result::Error(error.into_proto())),
                }
            }
        };
        Ok(Response::new(result))
    }

    /// Handles one unary authorization RPC from a local IPC client.
    ///
    /// This is a deliberately temporary allow-all stub so session-wrapper can
    /// build and test command mediation over the dedicated authorization IPC
    /// contract. Future work should replace this method body with real RFC 8907
    /// TACACS+ authorization forwarding behind the same protobuf contract.
    async fn authorization(
        &self,
        request: Request<ipc::AuthorizationRequest>,
    ) -> Result<Response<ipc::AuthorizationReply>, Status> {
        let request = AuthorizationOperation::try_from(request.into_inner()).map_err(|error| {
            log::warn!("Invalid IPC authorization request: {error}");
            Status::invalid_argument(error.to_string())
        })?;
        log::debug!(
            "Received IPC authorization request: user={}, service={}, cmd={}",
            request.user,
            request.service().unwrap_or("<missing>"),
            request.command().unwrap_or("<missing>"),
        );

        let response = AuthorizationOperationResponse {
            server: "stub".to_owned(),
            status: AuthorizationResponseStatus::PassAdd,
            server_message: "authorization allowed by temporary local stub; upstream TACACS+ authorization is not implemented yet".to_owned(),
            args: Vec::new(),
            data: String::new(),
        };

        Ok(Response::new(ipc::AuthorizationReply {
            result: Some(ipc::authorization_reply::Result::Response(response.into_proto())),
        }))
    }
}

impl TacacsClientService {
    /// Builds a TACACS+ client service with persistent upstream connections and
    /// ordered failover state.
    ///
    /// # Errors
    ///
    /// Returns an error if no upstream TACACS+ servers are configured or if
    /// credential-reference resolution fails.
    pub fn new(config: ServiceConfig) -> anyhow::Result<Self> {
        let servers = enumerate_accounting_servers(&config)?;

        let connector: Arc<dyn UpstreamConnector> = Arc::new(NetworkUpstreamConnector {
            disable_certificate_verification: config.disable_certificate_verification,
        });
        let state =
            Arc::new(ServiceState::new(servers, connector, config.preferred_probe_interval));

        Ok(Self { config, state })
    }

    #[cfg(all(test, unix))]
    pub(super) fn new_with_connector(
        config: ServiceConfig,
        connector: Arc<dyn UpstreamConnector>,
    ) -> anyhow::Result<Self> {
        let servers = enumerate_accounting_servers(&config)?;

        let state =
            Arc::new(ServiceState::new(servers, connector, config.preferred_probe_interval));

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
        log::info!("Warming upstream TACACS+ connections");
        self.state.warm_connections().await;
        let probe_task = if self.state.server_count() > 1 {
            log::info!(
                "Starting preferred-server probe task (interval: {:?})",
                self.config.preferred_probe_interval,
            );
            Some(self.state.spawn_preferred_probe())
        } else {
            None
        };

        let result = match &self.config.endpoint {
            #[cfg(unix)]
            IpcEndpoint::Unix(path) => self.serve_unix(path).await,
            IpcEndpoint::Tcp(address) => self.serve_tcp(*address).await,
        };

        if let Some(task) = probe_task {
            task.abort();
        }

        log::info!("TACACS+ client service has shut down");
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

        log::info!("Listening for IPC clients on Unix socket {}", path.display());

        tonic::transport::Server::builder()
            .add_service(TacacsAgentServer::new(grpc_service))
            .serve_with_incoming_shutdown(incoming, shutdown_signal())
            .await
            .with_context(|| format!("Unix IPC server {} failed", path.display()))?;

        log::info!("Shutdown signal received; draining active IPC clients");
        self.state.wait_for_active_clients().await;
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
                    tokio::fs::remove_file(path).await.with_context(|| {
                        format!("Failed to remove stale socket {}", path.display())
                    })?;
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
            log::error!("Refusing non-loopback TCP IPC endpoint: {address}");
            bail!("TCP IPC endpoint must be loopback-only: {address}");
        }

        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("Failed to bind TCP IPC endpoint {address}"))?;
        let incoming = TcpListenerStream::new(listener);
        let grpc_service = GrpcService {
            state: Arc::clone(&self.state),
        };

        log::info!("Listening for IPC clients on TCP {address}");

        tonic::transport::Server::builder()
            .add_service(TacacsAgentServer::new(grpc_service))
            .serve_with_incoming_shutdown(incoming, shutdown_signal())
            .await
            .with_context(|| format!("TCP IPC server {address} failed"))?;

        log::info!("Shutdown signal received; draining active IPC clients");
        self.state.wait_for_active_clients().await;
        Ok(())
    }
}

fn enumerate_accounting_servers(config: &ServiceConfig) -> anyhow::Result<Vec<TacacsPlusServer>> {
    let servers = tacacsrs_config::enumerate_servers(&config.tacacs_plus)?;
    let accounting_servers = servers
        .into_iter()
        .filter(|server| server.supports_server_type(TacacsPlusServerType::ACCOUNTING))
        .collect::<Vec<_>>();

    if accounting_servers.is_empty() {
        bail!("At least one accounting-capable TACACS+ server must be configured");
    }

    Ok(accounting_servers)
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

        if let Ok(mut terminate_signal) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    log::info!("Received Ctrl-C; initiating graceful shutdown");
                }
                _ = terminate_signal.recv() => {
                    log::info!("Received SIGTERM; initiating graceful shutdown");
                }
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
            log::info!("Received Ctrl-C; initiating graceful shutdown");
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Received Ctrl-C; initiating graceful shutdown");
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::collections::HashMap;
    #[cfg(unix)]
    use std::sync::Arc;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicBool, Ordering};
    #[cfg(unix)]
    use std::time::Duration;

    #[cfg(unix)]
    use tacacsrs_agent_client::{
        AuthorizationOperation, AuthorizationResponseStatus, IpcEndpoint, ServiceClient,
    };

    #[cfg(unix)]
    use super::TacacsClientService;
    #[cfg(unix)]
    use super::super::config::ServiceConfig;
    #[cfg(unix)]
    use super::super::test_support::{FakeConnection, FakeConnector, build_request};

    #[cfg(unix)]
    fn test_server(address: &str) -> tacacsrs_config::TacacsPlusServer {
        let (host, port) = match address.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(49)),
            None => (address.to_owned(), 49),
        };
        tacacsrs_config::TacacsPlusServer {
            name: address.to_owned(),
            server_type: tacacsrs_config::TacacsPlusServerType::ACCOUNTING,
            address: host,
            port,
            shared_secret: Some("test-secret".to_owned()),
            timeout: 5,
            single_connection: false,
            domain_name: None,
            sni_enabled: None,
            client_identity: None,
            server_authentication: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        }
    }

    #[cfg(unix)]
    fn service_config(
        endpoint: IpcEndpoint,
        servers: Vec<tacacsrs_config::TacacsPlusServer>,
    ) -> ServiceConfig {
        let tacacs_plus = servers
            .into_iter()
            .fold(
                tacacsrs_config::TacacsPlusBuilder::new(),
                tacacsrs_config::TacacsPlusBuilder::with_server,
            )
            .build()
            .expect("test config is valid");
        ServiceConfig {
            endpoint,
            tacacs_plus,
            preferred_probe_interval: Duration::from_millis(50),
            socket_mode: 0o660,
            disable_certificate_verification: false,
        }
    }

    #[cfg(unix)]
    #[test]
    fn service_uses_only_accounting_capable_servers() {
        let endpoint = test_endpoint("tacacs-service-accounting-filter");
        let mut auth_only = test_server("auth-only:49");
        auth_only.server_type = tacacsrs_config::TacacsPlusServerType::AUTHENTICATION;
        let accounting = test_server("accounting:49");
        let config = service_config(endpoint, vec![auth_only, accounting]);

        let connector = Arc::new(FakeConnector::new(HashMap::new()));
        let service = TacacsClientService::new_with_connector(config, connector).unwrap();

        assert_eq!(service.state.server_count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn service_rejects_config_without_accounting_server() {
        let endpoint = test_endpoint("tacacs-service-no-accounting");
        let mut auth_only = test_server("auth-only:49");
        auth_only.server_type = tacacsrs_config::TacacsPlusServerType::AUTHENTICATION;
        let config = service_config(endpoint, vec![auth_only]);

        let connector = Arc::new(FakeConnector::new(HashMap::new()));
        let Err(error) = TacacsClientService::new_with_connector(config, connector) else {
            panic!("accounting-capable server should be required");
        };

        assert!(error
            .to_string()
            .contains("At least one accounting-capable TACACS+ server"));
    }

    #[cfg(unix)]
    fn test_endpoint(socket_name: &str) -> IpcEndpoint {
        let unique = format!(
            "{}-{}-{}.sock",
            socket_name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        IpcEndpoint::Unix(std::path::PathBuf::from("/tmp").join(unique))
    }

    #[cfg(unix)]
    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real Unix socket + gRPC I/O
    async fn test_unix_socket_failover_and_preferred_recovery() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let secondary = Arc::new(FakeConnection {
            address: "secondary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (primary.address.clone(), Arc::clone(&primary)),
            (secondary.address.clone(), Arc::clone(&secondary)),
        ])));

        let endpoint = test_endpoint("tacacs-service-test");
        let config = service_config(
            endpoint.clone(),
            vec![test_server("primary:49"), test_server("secondary:49")],
        );

        let service = TacacsClientService::new_with_connector(config, connector).unwrap();
        let service_task = tokio::spawn(async move { service.serve().await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = ServiceClient::connect(endpoint.clone()).await.unwrap();
        let request = build_request();

        let first = client.send_accounting(request.clone()).await.unwrap();
        assert_eq!(first.server, "primary:49");

        primary.fail_next_request.store(true, Ordering::Relaxed);
        let failure = client.send_accounting(request.clone()).await.unwrap_err();
        let failure_msg = failure.to_string();
        assert!(
            failure_msg.contains("primary:49"),
            "Expected error mentioning primary:49, got: {failure_msg}"
        );

        let second = client.send_accounting(request.clone()).await.unwrap();
        assert_eq!(second.server, "secondary:49");

        primary.usable.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(120)).await;

        let third = client.send_accounting(request).await.unwrap();
        assert_eq!(third.server, "primary:49");

        service_task.abort();
        let _ = service_task.await;

        if let IpcEndpoint::Unix(path) = endpoint {
            let _ = tokio::fs::remove_file(path).await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real Unix socket + gRPC I/O
    async fn test_authorization_rpc_returns_temporary_allow_stub() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            primary.address.clone(),
            Arc::clone(&primary),
        )])));

        let endpoint = test_endpoint("tacacs-service-authorization-stub");
        let config = service_config(endpoint.clone(), vec![test_server("primary:49")]);

        let service = TacacsClientService::new_with_connector(config, connector).unwrap();
        let service_task = tokio::spawn(async move { service.serve().await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = ServiceClient::connect(endpoint.clone()).await.unwrap();
        let request = AuthorizationOperation::builder("admin", 0)
            .port("pts/1")
            .remote_address("127.0.0.1")
            .service("shell")
            .command("/bin/echo")
            .command_arg("hello")
            .build()
            .unwrap();
        let response = client.send_authorization(request).await.unwrap();

        assert_eq!(response.server, "stub");
        assert_eq!(response.status, AuthorizationResponseStatus::PassAdd);
        assert!(response.server_message.contains("temporary local stub"));
        assert!(response.args.is_empty());
        assert!(response.data.is_empty());

        service_task.abort();
        let _ = service_task.await;

        if let IpcEndpoint::Unix(path) = endpoint {
            let _ = tokio::fs::remove_file(path).await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real Unix socket + filesystem I/O
    async fn test_existing_socket_path_is_not_unlinked() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            primary.address.clone(),
            Arc::clone(&primary),
        )])));

        let endpoint = test_endpoint("tacacs-service-existing-socket");
        let path = match &endpoint {
            IpcEndpoint::Unix(path) => path.clone(),
            IpcEndpoint::Tcp(_) => unreachable!(),
        };

        let existing_listener = tokio::net::UnixListener::bind(&path).unwrap();
        let config = service_config(endpoint, vec![test_server("primary:49")]);

        let service = TacacsClientService::new_with_connector(config, connector).unwrap();
        let error = service.serve().await.unwrap_err();
        assert!(error.to_string().contains("already accepting connections"));

        drop(existing_listener);
        let _ = tokio::fs::remove_file(path).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real Unix socket + filesystem I/O
    async fn test_stale_socket_path_is_replaced() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            primary.address.clone(),
            Arc::clone(&primary),
        )])));

        let endpoint = test_endpoint("tacacs-service-stale-socket");
        let path = match &endpoint {
            IpcEndpoint::Unix(path) => path.clone(),
            IpcEndpoint::Tcp(_) => unreachable!(),
        };

        let stale_listener = tokio::net::UnixListener::bind(&path).unwrap();
        drop(stale_listener);

        let config = service_config(endpoint, vec![test_server("primary:49")]);

        let service = TacacsClientService::new_with_connector(config, connector).unwrap();
        let listener = service.prepare_unix_listener(&path).await.unwrap();
        drop(listener);

        assert!(tokio::fs::try_exists(&path).await.unwrap());
        let _ = tokio::fs::remove_file(path).await;
    }
}
