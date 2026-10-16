//! Runtime orchestration for the central TACACS+ client service.
//!
//! This module validates startup configuration and controls graceful listener
//! shutdown. It delegates request handling and failover decisions to
//! [`crate::upstream::manager::UpstreamManager`].
//!
//! # Startup sequence
//!
//! 1. [`TacacsClientService::new`] resolves the current upstream server set.
//! 2. [`TacacsClientService::serve`] publishes lazy connection state and binds
//!    each listener.
//! 3. The service accepts clients until it receives a shutdown signal.
//!
//! # Graceful shutdown
//!
//! Shutdown uses this sequence:
//!
//! 1. Each listener stops accepting connections.
//! 2. Admission closes and active request handlers drain under one deadline.
//! 3. Remaining listener tasks are cancelled and joined.
//! 4. Current and historical upstream resources close and join using that deadline.
//! 5. Owned Unix socket paths are removed before stopped state is published.

use std::sync::Arc;

use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::TacacsPlus;
use tacacsrs_config::local_services::{prepare_local_services, PreparedLocalServices, ListenerEndpoint};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use super::{
    RequestTracker, RuntimeHealthPublisher, ShutdownCoordinator, UpstreamAvailability,
    enumerate_supported_servers, ProxyLoopGuard,
};
use crate::config::{PreparedProxyPolicy, RuntimePolicy, ServiceConfig};
use crate::services::client_api::ClientApiService;
use crate::services::tacacs_proxy::TacacsProxyService;
use crate::services::ListenerOptions;
use crate::upstream::NetworkUpstreamConnector;
#[cfg(test)]
use crate::upstream::UpstreamConnector;
use crate::upstream::UpstreamConnection;
use crate::upstream::manager::UpstreamManager;
#[cfg(test)]
use crate::upstream::manager::ServiceConnector;
use tacacsrs_networking::routed::EndpointConnector;

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
    runtime: ServiceRuntime<NetworkUpstreamConnector>,
}

impl TacacsClientService {
    /// Builds a service with the concrete native connector.
    ///
    /// # Errors
    /// Returns a configuration or native preparation error.
    pub fn new(config: ServiceConfig, health: RuntimeHealthPublisher) -> anyhow::Result<Self> {
        Ok(Self {
            runtime: ServiceRuntime::from_config(
                config,
                health,
                true,
                NetworkUpstreamConnector::new,
            )?,
        })
    }

    /// Builds an empty service that waits for its first valid configuration.
    ///
    /// # Errors
    /// Returns an error for nonempty upstreams or invalid listener configuration.
    pub fn waiting_for_configuration(
        config: ServiceConfig,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.tacacs_plus.server.is_empty(),
            "Configuration for a waiting service must contain no TACACS+ servers"
        );
        Ok(Self {
            runtime: ServiceRuntime::from_config(
                config,
                health,
                false,
                NetworkUpstreamConnector::new,
            )?,
        })
    }

    /// Applies a complete validated upstream configuration.
    ///
    /// # Errors
    /// Returns a validation or preparation error without publishing a partial update.
    pub async fn reload_tacacs_plus(&self, source: TacacsPlus) -> anyhow::Result<()> {
        self.runtime.reload_tacacs_plus(source).await
    }

    /// Applies a validated policy to new requests.
    pub async fn reload_runtime_policy(&self, policy: RuntimePolicy) {
        self.runtime.reload_runtime_policy(policy).await;
    }

    /// Applies upstream configuration with its prepared downstream policy.
    ///
    /// # Errors
    /// Returns an error if the complete update cannot be prepared and published.
    pub async fn reload_tacacs_plus_with_proxy_downstream_obfuscation(
        &self,
        source: TacacsPlus,
        policy: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        self.runtime
            .reload_tacacs_plus_with_proxy_downstream_obfuscation(source, policy)
            .await
    }

    /// Applies materialized upstreams with their prepared downstream policy.
    ///
    /// # Errors
    /// Returns an error if validation or native preparation fails.
    pub async fn reload_materialized_servers_with_proxy_downstream_obfuscation(
        &self,
        servers: Vec<Arc<tacacsrs_config::TacacsPlusServer>>,
        policy: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        self.runtime
            .reload_materialized_servers_with_proxy_downstream_obfuscation(servers, policy)
            .await
    }

    /// Returns the current configured upstream count.
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.runtime.server_count()
    }

    /// Serves until a process shutdown signal and joins runtime resources.
    ///
    /// # Errors
    /// Returns a listener or shutdown error after cleanup.
    pub async fn serve(&self) -> anyhow::Result<()> {
        self.runtime.serve().await
    }

    /// Serves until an embedding host requests shutdown, without installing signals.
    ///
    /// # Errors
    /// Returns a listener or shutdown error after cleanup.
    pub async fn serve_until(
        &self,
        stop: impl std::future::Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        self.runtime.serve_until(stop).await
    }

    /// Closes upstream resources without starting listeners.
    ///
    /// Stop an active listener run through its `serve_until` trigger and await it.
    ///
    /// # Errors
    /// Returns an upstream cleanup error after joining remaining resources.
    pub async fn close_and_join(
        &self,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.runtime.close_and_join(deadline).await
    }
}

/// Generic service implementation shared by native production and test connectors.
pub(crate) struct ServiceRuntime<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    /// Validated operator configuration.
    config: ServiceConfig,
    listeners: PreparedLocalServices,
    proxy_loop_guard: ProxyLoopGuard,
    /// Shared failover state for all IPC request handlers.
    state: Arc<UpstreamManager<Connector>>,
    /// Serializes publication of a complete runtime generation.
    reload_lock: Mutex<()>,
    /// Shared request tracker for graceful shutdown.
    request_tracker: Arc<RequestTracker>,
    /// Shared protocol-neutral runtime health publisher.
    health: RuntimeHealthPublisher,
}

struct ServiceRunGuard<'service, Connector: EndpointConnector>(
    Option<&'service UpstreamManager<Connector>>,
);

impl<Connector: EndpointConnector> Drop for ServiceRunGuard<'_, Connector> {
    fn drop(&mut self) {
        if let Some(manager) = self.0 {
            manager.cancel();
        }
    }
}

#[cfg(test)]
impl ServiceRuntime<ServiceConnector> {
    /// Builds a TACACS+ client service with persistent server connections and
    /// ordered failover.
    ///
    /// # Errors
    ///
    /// Returns an error if schema validation, credential-reference expansion,
    /// capability checks, or native transport preparation fails.
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
        Self::from_config(config, health, configuration_applied, |guard| {
            ServiceConnector(NetworkUpstreamConnector::new(guard).erased())
        })
    }

    pub(super) fn new_with_connector(
        config: ServiceConfig,
        connector: Arc<UpstreamConnector>,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<Self> {
        Self::from_config(config, health, true, |_| ServiceConnector(connector))
    }
}

impl<Connector: EndpointConnector> ServiceRuntime<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    fn from_config(
        config: ServiceConfig,
        health: RuntimeHealthPublisher,
        configuration_applied: bool,
        factory: impl FnOnce(ProxyLoopGuard) -> Connector,
    ) -> anyhow::Result<Self> {
        let listeners = prepare_local_services(&config.local_services)?;
        let proxy_loop_guard = ProxyLoopGuard::new(listeners.tacacs_proxy());
        if health.snapshot().enabled_services() != config.enabled_services() {
            anyhow::bail!("Runtime health and service configuration must enable the same services");
        }
        let servers = enumerate_supported_servers(&config.tacacs_plus, &config.validation_options)?;
        let eligible_server_count = servers.len();

        let connector = factory(proxy_loop_guard.clone());
        let proxy_policy = if !configuration_applied
            && config.local_services.proxy_credential_source
                == tacacsrs_config::tacacsrs::ProxyCredentialSource::LocalProxyRow
        {
            PreparedProxyPolicy::unavailable()
        } else {
            tacacsrs_config::proxy_policy::prepare_proxy_policy(&config.local_services, None)?
        };
        let state = Arc::new(UpstreamManager::from_connector(
            servers.into_iter().map(Arc::new).collect(),
            proxy_policy,
            config.runtime_policy.clone(),
            connector,
            health.clone(),
            tacacsrs_config::prepare::PrepareOptions::default()
                .with_certificate_verification_disabled(config.disable_certificate_verification),
        )?);
        let request_tracker = Arc::new(RequestTracker::default());
        health.set_eligible_server_count(eligible_server_count);
        health.set_applied_configuration(configuration_applied);

        Ok(Self {
            config,
            listeners,
            proxy_loop_guard,
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
    /// Returns an error if validation, reference expansion, or native preparation
    /// fails. Failure leaves the active runtime generation unchanged.
    pub async fn reload_tacacs_plus(&self, tacacs_plus: TacacsPlus) -> anyhow::Result<()> {
        let _reload_guard = self.reload_lock.lock().await;
        let proxy_downstream_obfuscation = self
            .state
            .proxy_transport_settings()
            .downstream_obfuscation()
            .clone();
        self.reload_tacacs_plus_inner(tacacs_plus, proxy_downstream_obfuscation)
            .await
    }

    /// Atomically applies a validated runtime policy to new requests.
    pub async fn reload_runtime_policy(&self, runtime_policy: RuntimePolicy) {
        let _reload_guard = self.reload_lock.lock().await;
        self.state.reload_runtime_policy(runtime_policy);
    }

    /// Applies TACACS+ configuration and the downstream proxy obfuscation policy.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, reference expansion, or native preparation
    /// fails. Failure leaves the active runtime generation unchanged.
    pub async fn reload_tacacs_plus_with_proxy_downstream_obfuscation(
        &self,
        tacacs_plus: TacacsPlus,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        let _reload_guard = self.reload_lock.lock().await;
        self.reload_tacacs_plus_inner(tacacs_plus, proxy_downstream_obfuscation)
            .await
    }

    async fn reload_tacacs_plus_inner(
        &self,
        tacacs_plus: TacacsPlus,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        proxy_downstream_obfuscation.shared_secret()?;
        let servers = enumerate_supported_servers(&tacacs_plus, &self.config.validation_options)?;
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
    /// The caller must resolve credentials first. The service validates the full
    /// set and prepares native contexts before publication. New requests see only
    /// the complete replacement. Bound requests retain their previous server set.
    ///
    /// # Errors
    ///
    /// Returns an error if the service cannot apply the materialized server set.
    /// If it fails, the previous runtime state stays active.
    pub async fn reload_materialized_servers_with_proxy_downstream_obfuscation(
        &self,
        servers: Vec<Arc<tacacsrs_config::TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        proxy_downstream_obfuscation.shared_secret()?;
        tacacsrs_config::prepare::validate_materialized_servers(
            servers.iter().map(AsRef::as_ref),
            &self.config.validation_options,
        )?;
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

    /// Returns the number of configured TACACS+ servers.
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.state.server_count()
    }

    /// Runs the local service listeners until the process stops.
    ///
    /// Startup leaves operation connections unopened until their first request.
    /// If no eligible servers exist, the listeners still start. A later
    /// datastore reload can make the service ready without a process restart.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPC listener cannot be created or if the local
    /// endpoint configuration is invalid for the current platform.
    pub async fn serve(&self) -> anyhow::Result<()> {
        self.serve_until(super::shutdown::process_shutdown_signal())
            .await
    }

    /// Runs listeners until an embedding host requests shutdown, without installing signal handlers.
    ///
    /// The maximum current operation budget supplies one deadline for listener
    /// drain and all upstream retirement. The service cannot reopen after exit.
    ///
    /// # Errors
    /// Returns a listener, task, or upstream cleanup error after shutdown.
    pub async fn serve_until(
        &self,
        stop: impl std::future::Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        let shutdown = ShutdownCoordinator::new(self.health.clone());
        let serving = self.serve_with_shutdown(&shutdown);
        tokio::pin!(serving);
        tokio::select! {
            result = &mut serving => result,
            () = stop => { shutdown.initiate_shutdown(); serving.await }
        }
    }

    /// Permanently closes admission and joins upstream resources without starting listeners.
    ///
    /// # Errors
    /// Returns an upstream cleanup error after joining the remaining resources.
    pub async fn close_and_join(
        &self,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.state.close_and_join(deadline).await
    }

    async fn serve_with_shutdown(&self, shutdown: &ShutdownCoordinator) -> anyhow::Result<()> {
        self.state.ensure_open()?;
        let mut run = ServiceRunGuard(Some(&self.state));
        log::info!("Warming TACACS+ server connections");
        self.state.warm_connections();
        let result = self.serve_enabled_services(shutdown).await;
        run.0 = None;
        if result.is_ok() {
            shutdown.mark_stopped();
        } else {
            shutdown.fail();
        }

        log::info!("TACACS+ client service has shut down");
        result
    }

    async fn serve_enabled_services(&self, shutdown: &ShutdownCoordinator) -> anyhow::Result<()> {
        let listener_options = ListenerOptions::new(&self.listeners);
        let mut tasks = JoinSet::new();
        let mut service_count = 0;

        if let Some(path) = self.listeners.client_api() {
            let service =
                ClientApiService::new(Arc::clone(&self.state), Arc::clone(&self.request_tracker));
            let endpoint = IpcEndpoint::Unix(path.to_owned());
            let shutdown = shutdown.subscribe();
            let health = self.health.clone();
            tasks.spawn(async move {
                service
                    .serve(&endpoint, listener_options, shutdown, health)
                    .await
            });
            service_count += 1;
        }

        if let Some(target) = self.listeners.tacacs_proxy() {
            let service = TacacsProxyService::new(
                Arc::clone(&self.state),
                Arc::clone(&self.request_tracker),
                self.proxy_loop_guard.clone(),
            );
            let endpoint = match target {
                ListenerEndpoint::Unix(path) => IpcEndpoint::Unix(path.clone()),
                ListenerEndpoint::Tcp(address) => IpcEndpoint::Tcp(*address),
            };
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

        let stop = shutdown.subscribe().wait();
        tokio::pin!(stop);
        let mut failure = None;
        tokio::select! {
            biased;
            () = &mut stop => {},
            result = tasks.join_next() => {
                match result {
                    Some(Ok(Err(error))) => { failure = Some(error); shutdown.fail(); }
                    Some(Err(error)) => { failure = Some(error.into()); shutdown.fail(); }
                    Some(Ok(Ok(()))) => { shutdown.initiate_shutdown(); }
                    None => {},
                }
            }
        }
        let deadline = self.state.retirement_deadline()?;
        self.state.close();
        let draining = async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result
                    .map_err(anyhow::Error::from)
                    .and_then(std::convert::identity)
                {
                    failure.get_or_insert(error);
                }
            }
        };
        if deadline.run(draining).await.is_err() {
            tasks.shutdown().await;
        }
        let upstream = self.state.close_and_join(deadline).await;
        failure.map_or(upstream, Err)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tacacsrs_agent_client::ipc;
    use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgent;
    use tacacsrs_agent_client::{IpcEndpoint, ServiceClient};
    use tacacsrs_protocol::operations::{AuthorizationOperation, AuthorizationResponseStatus};
    use tonic::Request;

    use crate::config::{
        EnabledServices, FailoverStrategy, OperationPolicies, PreparedProxyPolicy, RuntimePolicy,
    };
    type TacacsClientService = super::ServiceRuntime<crate::upstream::manager::ServiceConnector>;
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
            local_services: tacacsrs_config::tacacsrs::LocalServices {
                client_api_endpoint: match endpoint {
                    IpcEndpoint::Unix(path) => path.to_str().unwrap().to_owned(),
                    IpcEndpoint::Tcp(address) => address.to_string(),
                },
                ..Default::default()
            },
            tacacs_plus,
            validation_options: tacacsrs_config::ValidationOptions::default(),
            runtime_policy: RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                Duration::from_millis(50),
            )
            .expect("test runtime policy"),
            disable_certificate_verification: false,
        }
    }

    fn test_service(config: ServiceConfig) -> anyhow::Result<TacacsClientService> {
        let health = RuntimeHealthPublisher::new(config.enabled_services());
        TacacsClientService::new(config, health)
    }

    #[test]
    fn conflicting_listener_endpoints_fail_before_binding() {
        let endpoint = test_endpoint("conflicting-listeners");
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.local_services.client_api_enabled = true;
        config.local_services.tacacs_proxy_enabled = true;
        config.local_services.tacacs_proxy_endpoint =
            Some(config.local_services.client_api_endpoint.clone());
        assert!(test_service(config).is_err());
    }

    #[tokio::test]
    async fn public_facade_uses_concrete_native_connector_through_ipc_and_shutdown() {
        use tacacsrs_networking::{PacketReader, PacketReadResult, PacketWriter, PacketWriteResult};
        use tacacsrs_protocol::accounting::reply::AccountingReply;
        use tacacsrs_protocol::enumerations::TacacsAccountingStatus;
        use tacacsrs_protocol::packet::{Packet, PacketTrait};
        use tacacsrs_protocol::traits::TacacsBodyTrait;

        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let server = test_server(&address);
            let endpoint = test_endpoint("concrete-production");
            let config = service_config(endpoint.clone(), vec![server]);
            let health = RuntimeHealthPublisher::new(config.enabled_services());
            let service =
                Arc::new(super::TacacsClientService::new(config, health.clone()).unwrap());
            let _: &UpstreamManager<crate::upstream::NetworkUpstreamConnector> =
                &service.runtime.state;
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let PacketReadResult::Success(request) =
                    PacketReader::new(Some(b"test-secret".to_vec()))
                        .read_packet(&mut stream)
                        .await
                else {
                    panic!("expected accounting packet");
                };
                let body = AccountingReply {
                    status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
                    server_msg: String::new(),
                    data: String::new(),
                }
                .to_bytes()
                .unwrap();
                let mut header = request.header().clone();
                header.seq_no += 1;
                header.length = u32::try_from(body.len()).unwrap();
                assert!(matches!(
                    PacketWriter::new(Some(b"test-secret".to_vec()))
                        .write_packet(&mut stream, Packet::new(header, body).unwrap())
                        .await,
                    PacketWriteResult::Success
                ));
            });
            let (stop, stopping) = tokio::sync::oneshot::channel();
            let running = service.clone();
            let task = tokio::spawn(async move {
                running
                    .serve_until(async {
                        let _signal = stopping.await;
                    })
                    .await
            });
            let mut updates = health.subscribe();
            updates
                .wait_for(|snapshot| snapshot.lifecycle() == RuntimeLifecycle::Serving)
                .await
                .unwrap();
            let client = ServiceClient::connect(endpoint).await.unwrap();
            assert_eq!(
                client
                    .send_accounting(build_request())
                    .await
                    .unwrap()
                    .server,
                address
            );
            stop.send(()).unwrap();
            task.await.unwrap().unwrap();
            peer.await.unwrap();
            assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
        })
        .await
        .expect("concrete production path must complete");
    }

    #[tokio::test]
    async fn downstream_credential_preparation_and_publication_preserve_active_generation() {
        use tacacsrs_config::proxy_policy::prepare_proxy_policy;
        use tacacsrs_config::tacacsrs::ProxyCredentialSource;
        use tacacsrs_secrets::SecretString;

        let mut config =
            service_config(test_endpoint("proxy-policy"), vec![test_server("primary:49")]);
        config.local_services.tacacs_proxy_enabled = true;
        config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:9050".to_owned());
        config.local_services.proxy_credential_source = ProxyCredentialSource::Inline;
        config.local_services.proxy_shared_secret =
            Some(SecretString::new("old-downstream-key".to_owned()));
        let source = config.local_services.clone();
        let service = test_service(config).unwrap();
        let old = service
            .state
            .proxy_transport_settings()
            .downstream_obfuscation()
            .clone();
        let health_before = format!("{:?}", service.health.snapshot());
        let mut invalid = source.clone();
        invalid.proxy_shared_secret = Some(SecretString::new(String::new()));
        assert!(prepare_proxy_policy(&invalid, None).is_err());
        assert!(service
            .reload_materialized_servers_with_proxy_downstream_obfuscation(
                Vec::new(),
                PreparedProxyPolicy::unavailable(),
            )
            .await
            .is_err());
        assert_eq!(service.server_count(), 1);
        assert_eq!(
            service
                .state
                .proxy_transport_settings()
                .downstream_obfuscation(),
            &old
        );
        assert_eq!(format!("{:?}", service.health.snapshot()), health_before);

        let mut replacement = source.clone();
        replacement.proxy_shared_secret = Some(SecretString::new("new-downstream-key".to_owned()));
        let prepared = prepare_proxy_policy(&replacement, None).unwrap();
        service
            .reload_materialized_servers_with_proxy_downstream_obfuscation(
                vec![Arc::new(test_server("primary:49"))],
                prepared.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .state
                .proxy_transport_settings()
                .downstream_obfuscation(),
            &prepared
        );
        assert_eq!(old.shared_secret().unwrap(), source.proxy_shared_secret.as_ref());
        assert_eq!(service.config.local_services, source);
    }

    #[test]
    fn waiting_proxy_cannot_treat_unresolved_row_credentials_as_plaintext() {
        let mut config =
            service_config(test_endpoint("pending-proxy"), vec![test_server("primary:49")]);
        config.tacacs_plus = tacacsrs_config::TacacsPlus::empty();
        config.local_services.tacacs_proxy_enabled = true;
        config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:49".to_owned());
        config.local_services.proxy_credential_source =
            tacacsrs_config::tacacsrs::ProxyCredentialSource::LocalProxyRow;
        let health = RuntimeHealthPublisher::new(config.enabled_services());
        let service = TacacsClientService::waiting_for_configuration(config, health).unwrap();
        assert!(service
            .state
            .proxy_transport_settings()
            .downstream_obfuscation()
            .shared_secret()
            .is_err());
    }

    #[tokio::test]
    async fn service_publication_preserves_explicit_source_validation_policy() {
        let mut plain = test_server("primary:49");
        plain.shared_secret = None;
        for allow_plain in [false, true] {
            let mut config =
                service_config(test_endpoint("validation-policy"), vec![test_server("primary:49")]);
            if allow_plain {
                config.validation_options = tacacsrs_config::ValidationOptions::new()
                    .with_relaxation(
                        tacacsrs_config::ValidationRelaxation::AllowPlainTcpWithoutSharedSecret,
                    );
            }
            let service = test_service(config.clone()).unwrap();
            let result = service
                .reload_materialized_servers_with_proxy_downstream_obfuscation(
                    vec![Arc::new(plain.clone())],
                    PreparedProxyPolicy::unobfuscated(),
                )
                .await;
            assert_eq!(result.is_ok(), allow_plain);
            config.tacacs_plus.server = vec![plain.clone()];
            assert_eq!(
                service
                    .reload_tacacs_plus(config.tacacs_plus.clone())
                    .await
                    .is_ok(),
                allow_plain
            );
            assert_eq!(test_service(config).is_ok(), allow_plain);
        }
    }

    fn test_service_with_connector(
        config: ServiceConfig,
        connector: Arc<crate::upstream::UpstreamConnector>,
    ) -> anyhow::Result<TacacsClientService> {
        let health = RuntimeHealthPublisher::new(config.enabled_services());
        TacacsClientService::new_with_connector(config, connector, health)
    }

    #[test]
    fn service_builds_independent_operation_catalogs() {
        let endpoint = test_endpoint("tacacs-service-runtime-filter");
        let mut partial = test_server("partial:49");
        partial.server_type = tacacsrs_config::TacacsPlusServerType::AUTHORIZATION
            | tacacsrs_config::TacacsPlusServerType::ACCOUNTING;
        let full = test_server("full:49");
        let config = service_config(endpoint, vec![partial, full]);

        let connector = Arc::new(FakeConnector::new(HashMap::new()));
        let service = test_service_with_connector(config, connector).unwrap();

        assert_eq!(service.state.server_count(), 2);
        assert_eq!(
            service
                .state
                .eligible_server_count(crate::OperationKind::Authentication),
            1
        );
        assert_eq!(
            service
                .state
                .eligible_server_count(crate::OperationKind::Authorization),
            2
        );
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

        assert_eq!(service.state.server_count(), 1);
        assert_eq!(
            service
                .state
                .eligible_server_count(crate::OperationKind::Authentication),
            0
        );
        assert_eq!(
            service
                .state
                .eligible_server_count(crate::OperationKind::Accounting),
            1
        );
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
            .contains("invalid local-services/client-api-endpoint"));
    }

    #[test]
    fn service_accepts_tcp_proxy_endpoint_on_unix() {
        let endpoint = test_endpoint("tacacs-service-proxy-tcp-client-api");
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.local_services.client_api_enabled = true;
        config.local_services.tacacs_proxy_enabled = true;
        config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:0".to_owned());

        let service =
            test_service(config).expect("the service must accept TCP proxy endpoints on Unix");

        assert_eq!(service.state.server_count(), 1);
    }

    #[test]
    fn service_rejects_invalid_disabled_client_api_endpoint() {
        let endpoint = IpcEndpoint::Tcp(
            "127.0.0.1:0"
                .parse()
                .expect("the test IPC endpoint must be valid"),
        );
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.local_services.client_api_enabled = false;
        config.local_services.tacacs_proxy_enabled = true;
        config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:1".to_owned());

        assert!(test_service(config).is_err());
    }

    #[test]
    fn service_rejects_no_enabled_runtime_services() {
        let endpoint = test_endpoint("tacacs-service-no-services");
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.local_services.client_api_enabled = false;
        config.local_services.tacacs_proxy_enabled = false;

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
        config.local_services.client_api_enabled = false;
        config.local_services.tacacs_proxy_enabled = true;

        let Err(error) = test_service(config) else {
            panic!("the service must reject proxy mode without an IPC endpoint");
        };

        assert!(error
            .to_string()
            .contains("The proxy endpoint must be present exactly when"));
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
            tacacsrs_protocol::operations::AuthorizationAuthenticationContext::TacacsAscii,
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
        assert_eq!(response.args, [] as [tacacsrs_protocol::operations::AuthorizationArg; 0]);
        assert_eq!(response.data, "");

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
            tacacsrs_protocol::operations::AuthorizationAuthenticationContext::TacacsAscii,
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
        assert!(!error.retriable);
        assert!(error.message.contains("Simulated failure"));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or TCP listeners.
    async fn both_listeners_bind_with_wildcard_proxy_before_startup_serves_and_cleanup_on_shutdown()
    {
        use std::os::unix::fs::PermissionsExt;

        let endpoint = test_endpoint("tacacs-service-both-listeners");
        let socket_path = match &endpoint {
            IpcEndpoint::Unix(path) => path.clone(),
            IpcEndpoint::Tcp(_) => {
                unreachable!("the test IPC endpoint must be a Unix domain socket")
            }
        };
        let mut config = service_config(endpoint, vec![test_server("primary:49")]);
        config.local_services.client_api_enabled = true;
        config.local_services.tacacs_proxy_enabled = true;
        config.local_services.tacacs_proxy_endpoint = Some("0.0.0.0:0".to_owned());
        config.local_services.unix_socket_mode = 0o600;
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
        assert_eq!(
            tokio::fs::metadata(&socket_path)
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

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
    async fn cancelled_serving_future_closes_retained_upstreams() {
        use tokio::io::AsyncReadExt;

        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config = service_config(
                test_endpoint("cancelled-service"),
                vec![test_server(&listener.local_addr().unwrap().to_string())],
            );
            let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
            let service = Arc::new(TacacsClientService::new(config, health.clone()).unwrap());
            let bound = service.state.bind_server_for_new_session().await.unwrap();
            let _conversation = bound.connection.open_conversation().await.unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let running = service.clone();
            let task =
                tokio::spawn(async move { running.serve_until(std::future::pending()).await });
            while health.snapshot().lifecycle() != RuntimeLifecycle::Serving {
                tokio::task::yield_now().await;
            }
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            service
                .close_and_join(
                    tacacsrs_networking::RequestDeadline::after(Duration::ZERO).unwrap(),
                )
                .await
                .unwrap();
            assert!(service.state.bind_server_for_new_session().await.is_err());
        })
        .await
        .expect("cancelled serving must not retain upstream sockets");
    }

    #[tokio::test]
    async fn embedded_shutdown_joins_retained_upstreams_and_prevents_restart() {
        use tokio::io::AsyncReadExt;
        use crate::config::RequestLimits;

        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = test_endpoint("embedded-close");
            let IpcEndpoint::Unix(path) = &endpoint else {
                unreachable!()
            };
            let path = path.clone();
            let mut config = service_config(
                endpoint,
                vec![test_server(&listener.local_addr().unwrap().to_string())],
            );
            let limits = RequestLimits::new(1024, 1)
                .unwrap()
                .with_request_timeout(Duration::from_millis(50))
                .unwrap();
            config.runtime_policy = RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::new(limits, limits, limits),
                Duration::from_secs(30),
            )
            .unwrap();
            let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
            let service = Arc::new(TacacsClientService::new(config, health.clone()).unwrap());
            let bound = service.state.bind_server_for_new_session().await.unwrap();
            let _conversation = bound.connection.open_conversation().await.unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let running = service.clone();
            let task = tokio::spawn(async move {
                running
                    .serve_until(async {
                        let _stop = stopped.await;
                    })
                    .await
            });
            while health.snapshot().lifecycle() != RuntimeLifecycle::Serving {
                tokio::task::yield_now().await;
            }
            let _ipc = ServiceClient::connect(IpcEndpoint::Unix(path.clone()))
                .await
                .unwrap();
            stop.send(()).unwrap();
            task.await.unwrap().unwrap();
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
            assert!(!tokio::fs::try_exists(&path).await.unwrap());
            assert!(bound.connection.open_conversation().await.is_err());
            assert!(service
                .reload_materialized_servers_with_proxy_downstream_obfuscation(
                    Vec::new(),
                    PreparedProxyPolicy::unobfuscated()
                )
                .await
                .is_err());
            service
                .close_and_join(
                    tacacsrs_networking::RequestDeadline::after(Duration::ZERO).unwrap(),
                )
                .await
                .unwrap();
            assert!(service.serve_until(std::future::pending()).await.is_err());
        })
        .await
        .expect("embedded shutdown must finish without process exit");
    }

    #[tokio::test]
    async fn ephemeral_proxy_binding_guards_production_clients_after_reload_and_shutdown() {
        use tacacsrs_networking::ConnectionGuard;

        let mut config =
            service_config(test_endpoint("ephemeral-guard"), vec![test_server("192.0.2.20:49")]);
        config.local_services.client_api_enabled = false;
        config.local_services.tacacs_proxy_enabled = true;
        config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:0".to_owned());
        let canonical = config.local_services.clone();
        let service = Arc::new(test_service(config).unwrap());
        let shutdown = ShutdownCoordinator::new(service.health.clone());
        let task = {
            let service = Arc::clone(&service);
            let shutdown = shutdown.clone();
            tokio::spawn(async move { service.serve_with_shutdown(&shutdown).await })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while service
                .health
                .snapshot()
                .listener(RuntimeService::TacacsProxy)
                != ListenerState::Bound
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let bound_address = service.proxy_loop_guard.bound_endpoint().unwrap().unwrap();
        assert_ne!(bound_address.port(), 0);
        service
            .reload_materialized_servers_with_proxy_downstream_obfuscation(
                vec![Arc::new(test_server(&bound_address.to_string()))],
                PreparedProxyPolicy::unobfuscated(),
            )
            .await
            .unwrap();
        let bound = service.state.bind_server_for_new_session().await.unwrap();
        let result =
            tokio::time::timeout(Duration::from_secs(2), bound.connection.open_conversation())
                .await
                .unwrap();
        let Err(error) = result else {
            panic!("production client connected to its proxy");
        };
        assert!(format!("{error:#}").contains("targets the local TACACS+ proxy"));
        assert_eq!(service.config.local_services, canonical);
        shutdown.initiate_shutdown();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(service
            .proxy_loop_guard
            .check_destination(bound_address)
            .is_err());
        assert!(bound.connection.open_conversation().await.is_err());
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
        config.local_services.client_api_enabled = true;
        config.local_services.tacacs_proxy_enabled = true;
        config.local_services.tacacs_proxy_endpoint = Some(occupied_address.to_string());
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
