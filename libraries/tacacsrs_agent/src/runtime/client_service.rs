//! Runtime orchestration for the central TACACS+ client service.
//!
//! This module owns process-level behavior: startup validation, IPC listener
//! graceful shutdown, and delegation into [`crate::upstream::manager::UpstreamManager`] for
//! per-client request handling and upstream failover decisions.
//!
//! # Startup sequence
//!
//! 1. [`TacacsClientService::new`] resolves the current upstream server set.
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

use std::sync::Arc;

use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::TacacsPlus;
use tokio::task::JoinSet;

use super::{RequestTracker, enumerate_supported_servers};
use crate::config::ServiceConfig;
use crate::services::client_api::ClientApiService;
use crate::services::tacacs_proxy::TacacsProxyService;
use crate::services::ListenerOptions;
use crate::upstream::{NetworkUpstreamConnector, UpstreamConnector};
use crate::upstream::manager::UpstreamManager;

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
    state: Arc<UpstreamManager>,
    /// Shared request lifecycle tracker used for graceful shutdown draining.
    request_tracker: Arc<RequestTracker>,
}

impl TacacsClientService {
    /// Builds a TACACS+ client service with persistent upstream connections and
    /// ordered failover state.
    ///
    /// # Errors
    ///
    /// Returns an error if credential-reference resolution fails.
    pub fn new(config: ServiceConfig) -> anyhow::Result<Self> {
        #[cfg(unix)]
        if config.enabled_services.client_api() {
            ClientApiService::validate_endpoint(&config.endpoint)?;
        }
        validate_enabled_services(&config)?;
        let servers = enumerate_supported_servers(&config)?;

        let connector: Arc<dyn UpstreamConnector> = Arc::new(NetworkUpstreamConnector {
            disable_certificate_verification: config.disable_certificate_verification,
        });
        let state =
            Arc::new(UpstreamManager::new(servers, connector, config.preferred_probe_interval));
        let request_tracker = Arc::new(RequestTracker::default());

        Ok(Self {
            config,
            state,
            request_tracker,
        })
    }

    #[cfg(all(test, unix))]
    pub(super) fn new_with_connector(
        config: ServiceConfig,
        connector: Arc<dyn UpstreamConnector>,
    ) -> anyhow::Result<Self> {
        if config.enabled_services.client_api() {
            ClientApiService::validate_endpoint(&config.endpoint)?;
        }
        validate_enabled_services(&config)?;
        let servers = enumerate_supported_servers(&config)?;

        let state =
            Arc::new(UpstreamManager::new(servers, connector, config.preferred_probe_interval));
        let request_tracker = Arc::new(RequestTracker::default());

        Ok(Self {
            config,
            state,
            request_tracker,
        })
    }

    /// Applies a validated TACACS+ configuration snapshot to the running service.
    ///
    /// # Errors
    ///
    /// Returns an error if credential-reference resolution fails. The existing
    /// runtime state is left unchanged on error.
    pub async fn reload_tacacs_plus(&self, tacacs_plus: TacacsPlus) -> anyhow::Result<()> {
        let mut reload_config = self.config.clone();
        reload_config.tacacs_plus = tacacs_plus;
        let servers = enumerate_supported_servers(&reload_config)?;
        self.state.reload_servers(servers).await
    }

    /// Returns the current number of accounting-capable upstream servers.
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.state.server_count()
    }

    /// Starts serving local IPC requests until the process is terminated.
    ///
    /// Startup first performs a best-effort warm-up of the first responsive
    /// upstream server and, when multiple servers are configured, launches the
    /// background probe that returns new sessions to the preferred server after
    /// recovery. If no upstream servers support the full current TACACS+
    /// operation set yet, the IPC listener still starts so later datastore
    /// reloads can make the service ready without a process restart.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPC listener cannot be created or if the local
    /// endpoint configuration is invalid for the current platform.
    pub async fn serve(&self) -> anyhow::Result<()> {
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

        let result = self.serve_enabled_services().await;

        if let Some(task) = probe_task {
            task.abort();
        }

        log::info!("TACACS+ client service has shut down");
        result
    }

    async fn serve_enabled_services(&self) -> anyhow::Result<()> {
        let listener_options = ListenerOptions::from_config(&self.config);
        let mut tasks = JoinSet::new();
        let mut service_count = 0;

        if self.config.enabled_services.client_api() {
            let service =
                ClientApiService::new(Arc::clone(&self.state), Arc::clone(&self.request_tracker));
            let endpoint = self.config.endpoint.clone();
            tasks.spawn(async move { service.serve(&endpoint, listener_options).await });
            service_count += 1;
        }

        if self.config.enabled_services.tacacs_proxy() {
            let service =
                TacacsProxyService::new(Arc::clone(&self.state), Arc::clone(&self.request_tracker));
            let endpoint = proxy_endpoint(&self.config)?.clone();
            tasks.spawn(async move { service.serve(&endpoint, listener_options).await });
            service_count += 1;
        }

        if service_count == 0 {
            anyhow::bail!("At least one runtime service must be enabled");
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tasks.abort_all();
                    return Err(error);
                }
                Err(error) => {
                    tasks.abort_all();
                    return Err(anyhow::anyhow!("Runtime service task failed: {error}"));
                }
            }
        }

        Ok(())
    }
}

fn proxy_endpoint(config: &ServiceConfig) -> anyhow::Result<&IpcEndpoint> {
    config
        .proxy_endpoint
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("The TACACS+ proxy service requires a proxy endpoint"))
}

fn validate_enabled_services(config: &ServiceConfig) -> anyhow::Result<()> {
    if config.enabled_services.is_empty() {
        anyhow::bail!("At least one runtime service must be enabled");
    }

    if config.enabled_services.tacacs_proxy() && config.proxy_endpoint.is_none() {
        anyhow::bail!("The TACACS+ proxy service requires a proxy endpoint");
    }

    if !config.enabled_services.tacacs_proxy() && config.proxy_endpoint.is_some() {
        anyhow::bail!("A proxy endpoint was configured, but the TACACS+ proxy service is disabled");
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tacacsrs_agent_client::ipc;
    use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgent;
    use tacacsrs_agent_client::{
        AuthorizationOperation, AuthorizationResponseStatus, IpcEndpoint, ServiceClient,
    };
    use tonic::Request;

    use crate::config::EnabledServices;
    use super::TacacsClientService;
    use crate::runtime::RequestTracker;
    use crate::runtime::REQUIRED_SERVER_TYPES;
    use crate::config::ServiceConfig;
    use crate::services::client_api::GrpcService;
    use crate::test_support::{FakeConnection, FakeConnector, build_request};
    use crate::upstream::manager::UpstreamManager;

    fn test_server(address: &str) -> tacacsrs_config::TacacsPlusServer {
        let (host, port) = match address.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(49)),
            None => (address.to_owned(), 49),
        };
        tacacsrs_config::TacacsPlusServer {
            name: address.to_owned(),
            server_type: REQUIRED_SERVER_TYPES,
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
            enabled_services: EnabledServices::CLIENT_API,
            endpoint,
            proxy_endpoint: None,
            tacacs_plus,
            preferred_probe_interval: Duration::from_millis(50),
            socket_mode: 0o660,
            disable_certificate_verification: false,
        }
    }

    #[test]
    fn service_uses_only_servers_supporting_runtime_operations() {
        let endpoint = test_endpoint("tacacs-service-runtime-filter");
        let mut partial = test_server("partial:49");
        partial.server_type = tacacsrs_config::TacacsPlusServerType::AUTHORIZATION
            | tacacsrs_config::TacacsPlusServerType::ACCOUNTING;
        let full = test_server("full:49");
        let config = service_config(endpoint, vec![partial, full]);

        let connector = Arc::new(FakeConnector::new(HashMap::new()));
        let service = TacacsClientService::new_with_connector(config, connector).unwrap();

        assert_eq!(service.state.server_count(), 1);
    }

    #[test]
    fn service_accepts_config_without_fully_capable_server() {
        let endpoint = test_endpoint("tacacs-service-no-full-server");
        let mut partial = test_server("partial:49");
        partial.server_type = tacacsrs_config::TacacsPlusServerType::AUTHORIZATION
            | tacacsrs_config::TacacsPlusServerType::ACCOUNTING;
        let config = service_config(endpoint, vec![partial]);

        let connector = Arc::new(FakeConnector::new(HashMap::new()));
        let service = TacacsClientService::new_with_connector(config, connector)
            .expect("service should accept waiting-for-config state");

        assert_eq!(service.state.server_count(), 0);
    }

    #[test]
    fn service_rejects_tcp_client_api_endpoint_on_unix() {
        let endpoint = IpcEndpoint::Tcp("127.0.0.1:0".parse().expect("test endpoint is valid"));
        let config = service_config(endpoint, vec![test_server("primary:49")]);

        let error = match TacacsClientService::new(config) {
            Ok(_) => panic!("service should reject TCP client API endpoints on Unix"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("Unix client API endpoints must use a Unix domain socket"));
    }

    #[test]
    fn service_accepts_tcp_proxy_endpoint_on_unix() {
        let endpoint = test_endpoint("tacacs-service-proxy-tcp-client-api");
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::BOTH;
        config.proxy_endpoint =
            Some(IpcEndpoint::Tcp("127.0.0.1:0".parse().expect("test endpoint is valid")));

        let service = TacacsClientService::new(config)
            .expect("service should accept TCP proxy endpoints on Unix");

        assert_eq!(service.state.server_count(), 1);
    }

    #[test]
    fn service_accepts_proxy_only_with_tcp_client_api_endpoint_on_unix() {
        let endpoint = IpcEndpoint::Tcp("127.0.0.1:0".parse().expect("test endpoint is valid"));
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::TACACS_PROXY;
        config.proxy_endpoint =
            Some(IpcEndpoint::Tcp("127.0.0.1:1".parse().expect("test endpoint is valid")));

        let service = TacacsClientService::new(config)
            .expect("proxy-only mode should not validate the disabled client API endpoint");

        assert_eq!(service.state.server_count(), 1);
    }

    #[test]
    fn service_rejects_no_enabled_runtime_services() {
        let endpoint = test_endpoint("tacacs-service-no-services");
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::NONE;

        let error = match TacacsClientService::new(config) {
            Ok(_) => panic!("service should reject configurations with no enabled services"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("At least one runtime service must be enabled"));
    }

    #[test]
    fn service_rejects_proxy_service_without_proxy_endpoint() {
        let endpoint = test_endpoint("tacacs-service-proxy-without-endpoint");
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::TACACS_PROXY;

        let error = match TacacsClientService::new(config) {
            Ok(_) => panic!("service should reject proxy mode without a proxy endpoint"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("The TACACS+ proxy service requires a proxy endpoint"));
    }

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

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // real Unix socket + gRPC I/O
    async fn test_authorization_rpc_uses_upstream_server() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            primary.address.clone(),
            Arc::clone(&primary),
        )])));

        let endpoint = test_endpoint("tacacs-service-authorization-upstream");
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

        assert_eq!(response.server, "primary:49");
        assert_eq!(response.status, AuthorizationResponseStatus::PassAdd);
        assert!(response.server_message.contains("authorized by primary:49"));
        assert!(response.args.is_empty());
        assert!(response.data.is_empty());

        service_task.abort();
        let _ = service_task.await;

        if let IpcEndpoint::Unix(path) = endpoint {
            let _ = tokio::fs::remove_file(path).await;
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio sync/time not supported
    async fn test_authorization_rpc_failure_returns_service_error_oneof() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(true),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            primary.address.clone(),
            Arc::clone(&primary),
        )])));
        let state = Arc::new(UpstreamManager::new(
            vec![test_server("primary:49")],
            connector,
            Duration::from_millis(50),
        ));
        let service = GrpcService::new(state, Arc::new(RequestTracker::default()));
        let request = AuthorizationOperation::builder("admin", 0)
            .port("pts/1")
            .remote_address("127.0.0.1")
            .service("shell")
            .command("/bin/echo")
            .command_arg("hello")
            .build()
            .unwrap();

        let reply = service
            .authorization(Request::new((&request).into()))
            .await
            .unwrap()
            .into_inner();

        let Some(ipc::authorization_reply::Result::Error(error)) = reply.result else {
            panic!("authorization failure should be returned in ServiceError oneof");
        };
        assert_eq!(error.server, "primary:49");
        assert!(error.retriable);
        assert!(error.message.contains("simulated failure"));
    }
}
