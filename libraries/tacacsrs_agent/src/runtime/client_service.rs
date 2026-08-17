//! Runtime orchestration for the central TACACS+ client service.
//!
//! This module validates startup configuration and controls graceful listener
//! shutdown. It delegates request handling and failover decisions to
//! [`crate::upstream::manager::UpstreamManager`].
//!
//! # Startup sequence
//!
//! 1. [`TacacsClientService::new`] resolves the current upstream server set.
//! 2. [`TacacsClientService::serve`] warms server connections. It starts the
//!    preferred-server probe when necessary and binds each listener.
//! 3. The service accepts clients until it receives a shutdown signal.
//!
//! # Graceful shutdown
//!
//! Shutdown uses this sequence:
//!
//! 1. Each listener stops accepting connections.
//! 2. Active request handlers finish.
//! 3. On Unix, the service removes the Unix domain socket path.

use std::sync::Arc;

use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::TacacsPlus;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use super::{
    RequestTracker, RuntimeHealthPublisher, ShutdownCoordinator, UpstreamAvailability,
    enumerate_supported_servers,
};
use crate::config::{ProxyDownstreamObfuscation, ServiceConfig};
use crate::services::client_api::ClientApiService;
use crate::services::tacacs_proxy::TacacsProxyService;
use crate::services::ListenerOptions;
use crate::upstream::{NetworkUpstreamConnector, UpstreamConnector};
use crate::upstream::manager::UpstreamManager;

/// Long-lived local TACACS+ client service.
///
/// [`TacacsClientService`] connects operator configuration to shared runtime
/// state. Its constructor validates the configuration and creates the failover
/// state machine. [`serve`](TacacsClientService::serve) starts the listeners.
///
/// This type is not `Clone` because it owns the listener lifecycle. Share
/// [`ServiceConfig`] before you create the service.
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
    /// Validated operator configuration.
    config: ServiceConfig,
    /// Shared failover state for all IPC request handlers.
    state: Arc<UpstreamManager>,
    /// Serializes publication of a complete runtime generation.
    reload_lock: Mutex<()>,
    /// Shared request tracker for graceful shutdown.
    request_tracker: Arc<RequestTracker>,
    /// Shared protocol-neutral runtime health publisher.
    health: RuntimeHealthPublisher,
}

impl TacacsClientService {
    /// Builds a TACACS+ client service with persistent server connections and
    /// ordered failover.
    ///
    /// # Errors
    ///
    /// Returns an error if credential-reference resolution fails.
    pub fn new(config: ServiceConfig, health: RuntimeHealthPublisher) -> anyhow::Result<Self> {
        Self::build(config, health, true)
    }

    /// Builds a service that can bind listeners before it receives valid
    /// configuration from the datastore.
    ///
    /// The placeholder configuration must contain no servers. A successful call
    /// to
    /// [`Self::reload_tacacs_plus_with_proxy_downstream_obfuscation`]
    /// marks the first configuration as applied.
    ///
    /// # Errors
    ///
    /// Returns an error if the placeholder contains a TACACS+ server. It also
    /// returns an error for invalid IPC endpoint configuration or a health
    /// publisher with a different service selection.
    pub fn waiting_for_configuration(
        config: ServiceConfig,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<Self> {
        if !config.tacacs_plus.server.is_empty() {
            anyhow::bail!("Configuration for a waiting service must contain no TACACS+ servers");
        }

        Self::build(config, health, false)
    }

    fn build(
        config: ServiceConfig,
        health: RuntimeHealthPublisher,
        configuration_applied: bool,
    ) -> anyhow::Result<Self> {
        #[cfg(unix)]
        if config.enabled_services.client_api() {
            ClientApiService::validate_endpoint(&config.endpoint)?;
        }
        validate_enabled_services(&config)?;
        if health.snapshot().enabled_services() != config.enabled_services {
            anyhow::bail!("Runtime health and service configuration must enable the same services");
        }
        let servers = enumerate_supported_servers(&config.tacacs_plus)?;
        let eligible_server_count = servers.len();

        let connector: Arc<dyn UpstreamConnector> = Arc::new(NetworkUpstreamConnector {
            disable_certificate_verification: config.disable_certificate_verification,
        });
        let state = Arc::new(UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
            servers.into_iter().map(Arc::new).collect(),
            config.proxy_downstream_obfuscation.clone(),
            connector,
            config.preferred_probe_interval,
            health.clone(),
        ));
        let request_tracker = Arc::new(RequestTracker::default());
        health.set_eligible_server_count(eligible_server_count);
        health.set_applied_configuration(configuration_applied);

        Ok(Self {
            config,
            state,
            reload_lock: Mutex::new(()),
            request_tracker,
            health,
        })
    }

    #[cfg(all(test, unix))]
    pub(super) fn new_with_connector(
        config: ServiceConfig,
        connector: Arc<dyn UpstreamConnector>,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<Self> {
        if config.enabled_services.client_api() {
            ClientApiService::validate_endpoint(&config.endpoint)?;
        }
        validate_enabled_services(&config)?;
        if health.snapshot().enabled_services() != config.enabled_services {
            anyhow::bail!("Runtime health and service configuration must enable the same services");
        }
        let servers = enumerate_supported_servers(&config.tacacs_plus)?;
        let eligible_server_count = servers.len();

        let state = Arc::new(UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
            servers.into_iter().map(Arc::new).collect(),
            config.proxy_downstream_obfuscation.clone(),
            connector,
            config.preferred_probe_interval,
            health.clone(),
        ));
        let request_tracker = Arc::new(RequestTracker::default());
        health.set_eligible_server_count(eligible_server_count);
        health.set_applied_configuration(true);

        Ok(Self {
            config,
            state,
            reload_lock: Mutex::new(()),
            request_tracker,
            health,
        })
    }

    /// Applies validated TACACS+ configuration to the running service.
    ///
    /// # Errors
    ///
    /// Returns an error if credential-reference resolution fails. If it fails,
    /// the method does not change the runtime state.
    pub async fn reload_tacacs_plus(&self, tacacs_plus: TacacsPlus) -> anyhow::Result<()> {
        let _reload_guard = self.reload_lock.lock().await;
        let proxy_downstream_obfuscation = self.state.proxy_downstream_obfuscation();
        self.reload_tacacs_plus_inner(tacacs_plus, proxy_downstream_obfuscation)
            .await
    }

    /// Applies TACACS+ configuration and the downstream proxy obfuscation policy.
    ///
    /// # Errors
    ///
    /// Returns an error if credential-reference resolution fails. If it fails,
    /// the method does not change the runtime state.
    pub async fn reload_tacacs_plus_with_proxy_downstream_obfuscation(
        &self,
        tacacs_plus: TacacsPlus,
        proxy_downstream_obfuscation: ProxyDownstreamObfuscation,
    ) -> anyhow::Result<()> {
        let _reload_guard = self.reload_lock.lock().await;
        self.reload_tacacs_plus_inner(tacacs_plus, proxy_downstream_obfuscation)
            .await
    }

    async fn reload_tacacs_plus_inner(
        &self,
        tacacs_plus: TacacsPlus,
        proxy_downstream_obfuscation: ProxyDownstreamObfuscation,
    ) -> anyhow::Result<()> {
        let mut reload_config = self.config.clone();
        reload_config.tacacs_plus = tacacs_plus;
        reload_config.proxy_downstream_obfuscation = proxy_downstream_obfuscation.clone();
        let servers = enumerate_supported_servers(&reload_config.tacacs_plus)?;
        let eligible_server_count = servers.len();
        self.state
            .reload_shared_servers_with_proxy_downstream_obfuscation(
                servers.into_iter().map(Arc::new).collect(),
                proxy_downstream_obfuscation,
            )
            .await?;
        self.health.set_eligible_server_count(eligible_server_count);
        self.health.set_applied_configuration(true);
        self.health
            .set_upstream_availability(UpstreamAvailability::Unknown);
        Ok(())
    }

    /// Atomically applies materialized servers and the proxy policy.
    ///
    /// The caller must validate and resolve each server first. New requests see
    /// only the complete replacement. Bound requests continue to use the
    /// previous immutable server set.
    ///
    /// # Errors
    ///
    /// Returns an error if the service cannot apply the materialized server set.
    /// If it fails, the previous runtime state stays active.
    pub async fn reload_materialized_servers_with_proxy_downstream_obfuscation(
        &self,
        servers: Vec<Arc<tacacsrs_config::TacacsPlusServer>>,
        proxy_downstream_obfuscation: ProxyDownstreamObfuscation,
    ) -> anyhow::Result<()> {
        let _reload_guard = self.reload_lock.lock().await;
        let eligible_server_count = servers.len();
        self.state
            .reload_shared_servers_with_proxy_downstream_obfuscation(
                servers,
                proxy_downstream_obfuscation,
            )
            .await?;
        self.health.set_eligible_server_count(eligible_server_count);
        self.health.set_applied_configuration(true);
        self.health
            .set_upstream_availability(UpstreamAvailability::Unknown);
        Ok(())
    }

    /// Returns the number of servers that support all required operations.
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.state.server_count()
    }

    /// Runs the local service listeners until the process stops.
    ///
    /// Startup tries to warm the first responsive server connection. When
    /// multiple servers exist, it starts a background preferred-server probe.
    /// If no eligible servers exist, the listeners still start. A later
    /// datastore reload can make the service ready without a process restart.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPC listener cannot be created or if the local
    /// endpoint configuration is invalid for the current platform.
    pub async fn serve(&self) -> anyhow::Result<()> {
        let shutdown = ShutdownCoordinator::new(self.health.clone());
        let signal_monitor = shutdown.spawn_process_signal_monitor();
        let result = self.serve_with_shutdown(&shutdown).await;
        signal_monitor.abort();
        result
    }

    async fn serve_with_shutdown(&self, shutdown: &ShutdownCoordinator) -> anyhow::Result<()> {
        log::info!("Warming TACACS+ server connections");
        self.state.warm_connections().await;
        log::info!(
            "Starting the preferred-server probe with interval {:?}",
            self.config.preferred_probe_interval,
        );
        let probe_task = self.state.spawn_preferred_probe();

        let result = self.serve_enabled_services(shutdown).await;
        probe_task.abort();
        if result.is_ok() {
            shutdown.mark_stopped();
        }

        log::info!("TACACS+ client service has shut down");
        result
    }

    async fn serve_enabled_services(&self, shutdown: &ShutdownCoordinator) -> anyhow::Result<()> {
        let listener_options = ListenerOptions::from_config(&self.config);
        let mut tasks = JoinSet::new();
        let mut service_count = 0;

        if self.config.enabled_services.client_api() {
            let service =
                ClientApiService::new(Arc::clone(&self.state), Arc::clone(&self.request_tracker));
            let endpoint = self.config.endpoint.clone();
            let shutdown = shutdown.subscribe();
            let health = self.health.clone();
            tasks.spawn(async move {
                service
                    .serve(&endpoint, listener_options, shutdown, health)
                    .await
            });
            service_count += 1;
        }

        if self.config.enabled_services.tacacs_proxy() {
            let service =
                TacacsProxyService::new(Arc::clone(&self.state), Arc::clone(&self.request_tracker));
            let endpoint = proxy_endpoint(&self.config)?.clone();
            let shutdown = shutdown.subscribe();
            let health = self.health.clone();
            tasks.spawn(async move {
                service
                    .serve(&endpoint, listener_options, shutdown, health)
                    .await
            });
            service_count += 1;
        }

        if service_count == 0 {
            anyhow::bail!("Enable at least one runtime service");
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    shutdown.fail();
                    tasks.shutdown().await;
                    return Err(error);
                }
                Err(error) => {
                    shutdown.fail();
                    tasks.shutdown().await;
                    return Err(anyhow::anyhow!("A runtime service task failed: {error}"));
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
        .ok_or_else(|| anyhow::anyhow!("The TACACS+ proxy service requires an IPC endpoint"))
}

fn validate_enabled_services(config: &ServiceConfig) -> anyhow::Result<()> {
    if config.enabled_services.is_empty() {
        anyhow::bail!("Enable at least one runtime service");
    }

    if config.enabled_services.tacacs_proxy() && config.proxy_endpoint.is_none() {
        anyhow::bail!("The TACACS+ proxy service requires an IPC endpoint");
    }

    if !config.enabled_services.tacacs_proxy() && config.proxy_endpoint.is_some() {
        anyhow::bail!("Remove the proxy IPC endpoint or enable the TACACS+ proxy service");
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

    use crate::config::{EnabledServices, ProxyDownstreamObfuscation};
    use super::TacacsClientService;
    use crate::runtime::{
        ListenerState, REQUIRED_SERVER_TYPES, RequestTracker, RuntimeHealthPublisher,
        RuntimeLifecycle, RuntimeService, ShutdownCoordinator,
    };
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
            shared_secret: Some(tacacsrs_secrets::SecretString::new("test-secret".to_owned())),
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
            .expect("the test configuration must be valid");
        ServiceConfig {
            enabled_services: EnabledServices::CLIENT_API,
            endpoint,
            proxy_endpoint: None,
            proxy_downstream_obfuscation: ProxyDownstreamObfuscation::default(),
            tacacs_plus,
            preferred_probe_interval: Duration::from_millis(50),
            socket_mode: 0o660,
            disable_certificate_verification: false,
        }
    }

    fn test_service(config: ServiceConfig) -> anyhow::Result<TacacsClientService> {
        let health = RuntimeHealthPublisher::new(config.enabled_services);
        TacacsClientService::new(config, health)
    }

    fn test_service_with_connector(
        config: ServiceConfig,
        connector: Arc<dyn crate::upstream::UpstreamConnector>,
    ) -> anyhow::Result<TacacsClientService> {
        let health = RuntimeHealthPublisher::new(config.enabled_services);
        TacacsClientService::new_with_connector(config, connector, health)
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
        let service = test_service_with_connector(config, connector).unwrap();

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
        let service = test_service_with_connector(config, connector)
            .expect("the service must accept a waiting state");

        assert_eq!(service.state.server_count(), 0);
    }

    #[test]
    fn service_rejects_tcp_client_api_endpoint_on_unix() {
        let endpoint = IpcEndpoint::Tcp(
            "127.0.0.1:0"
                .parse()
                .expect("the test IPC endpoint must be valid"),
        );
        let config = service_config(endpoint, vec![test_server("primary:49")]);

        let Err(error) = test_service(config) else {
            panic!("the service must reject TCP client API endpoints on Unix");
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
        config.proxy_endpoint = Some(IpcEndpoint::Tcp(
            "127.0.0.1:0"
                .parse()
                .expect("the test IPC endpoint must be valid"),
        ));

        let service =
            test_service(config).expect("the service must accept TCP proxy endpoints on Unix");

        assert_eq!(service.state.server_count(), 1);
    }

    #[test]
    fn service_accepts_proxy_only_with_tcp_client_api_endpoint_on_unix() {
        let endpoint = IpcEndpoint::Tcp(
            "127.0.0.1:0"
                .parse()
                .expect("the test IPC endpoint must be valid"),
        );
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::TACACS_PROXY;
        config.proxy_endpoint = Some(IpcEndpoint::Tcp(
            "127.0.0.1:1"
                .parse()
                .expect("the test IPC endpoint must be valid"),
        ));

        let service = test_service(config)
            .expect("proxy-only mode must not validate the disabled client API endpoint");

        assert_eq!(service.state.server_count(), 1);
    }

    #[test]
    fn service_rejects_no_enabled_runtime_services() {
        let endpoint = test_endpoint("tacacs-service-no-services");
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::NONE;

        let Err(error) = test_service(config) else {
            panic!("the service must reject configuration with no enabled services");
        };

        assert!(error
            .to_string()
            .contains("Enable at least one runtime service"));
    }

    #[test]
    fn service_rejects_proxy_service_without_proxy_endpoint() {
        let endpoint = test_endpoint("tacacs-service-proxy-without-endpoint");
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::TACACS_PROXY;

        let Err(error) = test_service(config) else {
            panic!("the service must reject proxy mode without an IPC endpoint");
        };

        assert!(error
            .to_string()
            .contains("The TACACS+ proxy service requires an IPC endpoint"));
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
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or gRPC I/O.
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

        let service = test_service_with_connector(config, connector).unwrap();
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
            "the error must contain primary:49: {failure_msg}"
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
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or gRPC I/O.
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

        let service = test_service_with_connector(config, connector).unwrap();
        let service_task = tokio::spawn(async move { service.serve().await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = ServiceClient::connect(endpoint.clone()).await.unwrap();
        let request = AuthorizationOperation::builder(
            "admin",
            0,
            tacacsrs_agent_client::AuthorizationAuthenticationContext::TacacsAscii,
        )
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
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio synchronization or time.
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
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
        ));
        let service = GrpcService::new(state, Arc::new(RequestTracker::default()));
        let request = AuthorizationOperation::builder(
            "admin",
            0,
            tacacsrs_agent_client::AuthorizationAuthenticationContext::TacacsAscii,
        )
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
            panic!("the ServiceError oneof must contain the authorization error");
        };
        assert_eq!(error.server, "primary:49");
        assert!(error.retriable);
        assert!(error.message.contains("Simulated failure"));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or TCP listeners.
    async fn both_listeners_bind_before_startup_serves_and_cleanup_on_shutdown() {
        let endpoint = test_endpoint("tacacs-service-both-listeners");
        let socket_path = match &endpoint {
            IpcEndpoint::Unix(path) => path.clone(),
            IpcEndpoint::Tcp(_) => {
                unreachable!("the test IPC endpoint must be a Unix domain socket")
            }
        };
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::BOTH;
        config.proxy_endpoint = Some(IpcEndpoint::Tcp(
            "127.0.0.1:0"
                .parse()
                .expect("the proxy IPC endpoint must be valid"),
        ));
        let health = RuntimeHealthPublisher::new(EnabledServices::BOTH);
        let upstream = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector =
            Arc::new(FakeConnector::new(HashMap::from([(upstream.address.clone(), upstream)])));
        let service = Arc::new(
            TacacsClientService::new_with_connector(config, connector, health.clone())
                .expect("the service must build"),
        );
        let shutdown = ShutdownCoordinator::new(health.clone());
        let task = {
            let service = Arc::clone(&service);
            let shutdown = shutdown.clone();
            tokio::spawn(async move { service.serve_with_shutdown(&shutdown).await })
        };

        tokio::time::timeout(Duration::from_secs(2), async {
            while health.snapshot().lifecycle() != RuntimeLifecycle::Serving {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both listeners must bind");
        assert!(health.snapshot().is_startup_serving());
        assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Bound,);
        assert_eq!(health.snapshot().listener(RuntimeService::TacacsProxy), ListenerState::Bound,);

        shutdown.initiate_shutdown();
        task.await
            .expect("the service task must stop")
            .expect("shutdown must succeed");

        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
        assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Stopped,);
        assert_eq!(health.snapshot().listener(RuntimeService::TacacsProxy), ListenerState::Stopped,);
        assert!(!tokio::fs::try_exists(socket_path)
            .await
            .expect("the socket inspection must succeed"));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or TCP listeners.
    async fn listener_bind_failure_aborts_sibling_without_publishing_readiness() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the test must occupy the proxy IPC endpoint");
        let occupied_address = occupied
            .local_addr()
            .expect("the occupied IPC endpoint must have an address");
        let endpoint = test_endpoint("tacacs-service-bind-failure");
        let socket_path = match &endpoint {
            IpcEndpoint::Unix(path) => path.clone(),
            IpcEndpoint::Tcp(_) => {
                unreachable!("the test IPC endpoint must be a Unix domain socket")
            }
        };
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.enabled_services = EnabledServices::BOTH;
        config.proxy_endpoint = Some(IpcEndpoint::Tcp(occupied_address));
        let health = RuntimeHealthPublisher::new(EnabledServices::BOTH);
        let upstream = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector =
            Arc::new(FakeConnector::new(HashMap::from([(upstream.address.clone(), upstream)])));
        let service = TacacsClientService::new_with_connector(config, connector, health.clone())
            .expect("the service must build");
        let shutdown = ShutdownCoordinator::new(health.clone());

        let result = service.serve_with_shutdown(&shutdown).await;

        assert!(result.is_err());
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
        assert!(!health.snapshot().is_readiness_serving());
        assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Stopped,);
        assert_eq!(health.snapshot().listener(RuntimeService::TacacsProxy), ListenerState::Stopped,);
        assert!(!tokio::fs::try_exists(socket_path)
            .await
            .expect("the socket inspection must succeed"));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or listener drain.
    async fn shutdown_withdraws_health_before_active_requests_finish_draining() {
        let endpoint = test_endpoint("tacacs-service-active-drain");
        let config = service_config(endpoint, vec![test_server("primary:49")]);
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let upstream = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector =
            Arc::new(FakeConnector::new(HashMap::from([(upstream.address.clone(), upstream)])));
        let service = Arc::new(
            TacacsClientService::new_with_connector(config, connector, health.clone())
                .expect("the service must build"),
        );
        let active_request = service.request_tracker.start_request();
        let shutdown = ShutdownCoordinator::new(health.clone());
        let mut task = {
            let service = Arc::clone(&service);
            let shutdown = shutdown.clone();
            tokio::spawn(async move { service.serve_with_shutdown(&shutdown).await })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while health.snapshot().lifecycle() != RuntimeLifecycle::Serving {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the listener must bind");

        shutdown.initiate_shutdown();
        tokio::task::yield_now().await;

        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Draining);
        assert!(!health.snapshot().is_liveness_serving());
        assert!(tokio::time::timeout(Duration::from_millis(25), &mut task)
            .await
            .is_err());

        drop(active_request);
        task.await
            .expect("the service task must stop")
            .expect("the drain must finish");
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
    }
}
