//! Internal service for upstream TACACS+ server selection and failover.
//!
//! All listener tasks share `UpstreamManager`. It owns operation-specific
//! server cursors, circuits, and cached connections.
//!
//! # Concurrency model
//!
//! Multiple IPC handlers can call `UpstreamManager` at the same time. The
//! manager uses small lock scopes to reduce contention.
//!
//! | Lock | Scope | Purpose |
//! |------|-------|---------|
//! | operation cursor (`RwLock`) | Per-operation | Current preferred server |
//! | connection (`RwLock`) | Per-server-operation | Cached connection |
//! | connect lock (`Mutex`) | Per-server-operation | Serializes reconnects |
//!
//! The `connect_lock` makes concurrent IPC handlers share one reconnect
//! attempt. It prevents duplicate TLS handshakes to one TACACS+ server.

use std::sync::{Arc, RwLock as StdRwLock};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};

use self::availability::AvailabilityTracker;
use self::server_set::{RuntimeRoutingSnapshot, ServerSet};
use self::server_slot::ServerSlot;
use crate::config::{ProxyDownstreamObfuscation, RuntimePolicy};
#[cfg(test)]
use crate::config::{FailoverStrategy, OperationPolicies};
use crate::runtime::RuntimeHealthPublisher;
use crate::upstream::admission::AdmissionRegistry;
use crate::upstream::{AdmissionError, OperationKind, ProxyTransportSettings, UpstreamConnector};

pub(crate) use self::server_set::BoundServer;

mod server_set;
mod server_slot;
mod availability;
mod circuit;
mod routing;

/// Shared server state for all IPC request handlers.
///
/// Each IPC request uses this type to select a TACACS+ server. The request
/// handler runs the operation and records failures for later requests.
///
/// Each operation walks its eligible server list from its active cursor. A
/// failure moves only that operation. One real request tests recovery after the
/// configured interval.
pub(crate) struct UpstreamManager {
    /// Current immutable routing generation for new requests.
    runtime: StdRwLock<Arc<RuntimeRoutingSnapshot>>,
    /// Factory for new server connections.
    connector: Arc<dyn UpstreamConnector>,
    /// Race-safe aggregate server-availability publisher.
    availability: AvailabilityTracker,
}

impl UpstreamManager {
    /// Creates shared failover state for the service runtime.
    ///
    /// The runtime can start without a configured server while it waits for
    /// external configuration. In this state, IPC requests immediately return
    /// a retriable configuration error.
    #[cfg(test)]
    pub(crate) fn new(
        servers: Vec<TacacsPlusServer>,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        let servers = servers.into_iter().map(Arc::new).collect();
        Self::new_shared_with_proxy_downstream_obfuscation(
            servers,
            ProxyDownstreamObfuscation::default(),
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                preferred_probe_interval,
            )
            .expect("test recovery interval must be nonzero"),
            connector,
            health,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_shared(
        servers: Vec<Arc<TacacsPlusServer>>,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        Self::new_shared_with_proxy_downstream_obfuscation(
            servers,
            ProxyDownstreamObfuscation::default(),
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                preferred_probe_interval,
            )
            .expect("test recovery interval must be nonzero"),
            connector,
            health,
        )
    }

    pub(crate) fn new_shared_with_proxy_downstream_obfuscation(
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: ProxyDownstreamObfuscation,
        runtime_policy: RuntimePolicy,
        connector: Arc<dyn UpstreamConnector>,
        health: RuntimeHealthPublisher,
    ) -> Self {
        let servers = servers
            .into_iter()
            .map(ServerSlot::new)
            .map(Arc::new)
            .collect();
        let server_set = Arc::new(ServerSet::new(servers));
        Self {
            runtime: StdRwLock::new(Arc::new(RuntimeRoutingSnapshot {
                server_set,
                proxy_downstream_obfuscation,
                admission: Arc::new(AdmissionRegistry::new(&runtime_policy)),
                runtime_policy: Arc::new(runtime_policy),
            })),
            connector,
            availability: AvailabilityTracker::new(health),
        }
    }

    fn current_runtime(&self) -> Arc<RuntimeRoutingSnapshot> {
        Arc::clone(
            &self
                .runtime
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn current_server_set(&self) -> Arc<ServerSet> {
        Arc::clone(&self.current_runtime().server_set)
    }

    pub(crate) fn proxy_transport_settings(&self) -> ProxyTransportSettings {
        let runtime = self.current_runtime();
        let read_timeout = runtime
            .server_set
            .servers
            .iter()
            .map(|server| server.config().timeout_duration())
            .max()
            .unwrap_or_else(|| std::time::Duration::from_secs(5));
        ProxyTransportSettings::new(read_timeout, runtime.proxy_downstream_obfuscation.clone())
    }

    /// Returns the current immutable runtime policy.
    pub(crate) fn runtime_policy(&self) -> Arc<RuntimePolicy> {
        Arc::clone(&self.current_runtime().runtime_policy)
    }

    /// Atomically replaces the runtime policy for new requests.
    pub(crate) fn reload_runtime_policy(&self, runtime_policy: RuntimePolicy) {
        let previous = self.current_runtime();
        previous.admission.update(&runtime_policy);
        let mut current = self
            .runtime
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = Arc::new(RuntimeRoutingSnapshot {
            server_set: Arc::clone(&previous.server_set),
            proxy_downstream_obfuscation: previous.proxy_downstream_obfuscation.clone(),
            admission: Arc::clone(&previous.admission),
            runtime_policy: Arc::new(runtime_policy),
        });
    }

    /// Records startup state without opening cross-operation probe sessions.
    pub(crate) fn warm_connections(&self) {
        let server_set = self.current_server_set();
        if server_set.server_count() == 0 {
            log::warn!("No TACACS+ server is configured; waiting for configuration");
            return;
        }
        log::info!(
            "Configured {} TACACS+ server(s); operation connections will open on first use",
            server_set.server_count()
        );
    }

    /// Returns the number of configured TACACS+ servers.
    pub(crate) fn server_count(&self) -> usize {
        self.current_server_set().server_count()
    }

    /// Returns the number of servers eligible for one operation.
    pub(crate) fn eligible_server_count(&self, operation: OperationKind) -> usize {
        self.current_server_set().route(operation).server_count()
    }

    /// Builds the retry plan for one local operation request.
    ///
    /// Services reach this through [`crate::upstream::OperationRouter`].
    pub(in crate::upstream) fn failover_plan(
        &self,
        service: crate::config::PolicyService,
        operation: OperationKind,
    ) -> crate::upstream::FailoverPlan {
        crate::upstream::FailoverPlan::new(
            &self.runtime_policy(),
            service,
            operation,
            self.eligible_server_count(operation),
        )
    }

    /// Waits for service-operation capacity from the current policy generation.
    ///
    /// Services reach this through [`crate::upstream::OperationRouter`].
    pub(in crate::upstream) async fn admit_request(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<crate::upstream::AdmissionPermit, AdmissionError> {
        let runtime = self.current_runtime();
        let route = runtime.server_set.route(operation);
        let wait_timeout = if route.server_count() == 0 {
            std::time::Duration::ZERO
        } else {
            let position = route.active_position().await;
            runtime.server_set.servers[route.server_index(position)]
                .config()
                .timeout_duration()
        };
        runtime
            .admission
            .acquire(operation, body_length, wait_timeout)
            .await
    }

    /// Validates one packet body without acquiring another concurrency permit.
    ///
    /// Services reach this through [`crate::upstream::OperationRouter`].
    pub(in crate::upstream) fn validate_request_size(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<(), AdmissionError> {
        self.current_runtime()
            .admission
            .validate_body_length(operation, body_length)
    }

    /// Atomically replaces the configured TACACS+ server set.
    ///
    /// New IPC requests use the new ordered server set. Bound requests continue
    /// to use their existing connections. The manager keeps cached connections
    /// for unchanged servers. Connections for removed or changed servers stop
    /// accepting new sessions and leave the active runtime state.
    #[cfg(test)]
    pub(crate) async fn reload_servers(
        &self,
        servers: Vec<TacacsPlusServer>,
    ) -> anyhow::Result<()> {
        self.reload_shared_servers(servers.into_iter().map(Arc::new).collect())
            .await
    }

    #[cfg(test)]
    pub(crate) async fn reload_shared_servers(
        &self,
        servers: Vec<Arc<TacacsPlusServer>>,
    ) -> anyhow::Result<()> {
        let proxy_downstream_obfuscation = self
            .proxy_transport_settings()
            .downstream_obfuscation()
            .clone();
        self.reload_shared_servers_with_proxy_downstream_obfuscation(
            servers,
            proxy_downstream_obfuscation,
        )
        .await
    }

    pub(crate) async fn reload_shared_servers_with_proxy_downstream_obfuscation(
        &self,
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: ProxyDownstreamObfuscation,
    ) -> anyhow::Result<()> {
        let previous = self.current_server_set();
        let materially_changed = previous.server_count() != servers.len()
            || previous
                .servers
                .iter()
                .zip(&servers)
                .any(|(old, new)| old.server.as_ref() != new.as_ref());
        let mut previous_active_names = Vec::with_capacity(OperationKind::ALL.len());
        for operation in OperationKind::ALL {
            previous_active_names.push(
                previous
                    .route(operation)
                    .active_server_name(&previous.servers)
                    .await,
            );
        }

        let mut new_server_slots = Vec::with_capacity(servers.len());
        for server in servers {
            let reusable = previous
                .servers
                .iter()
                .find(|state| state.server.as_ref() == server.as_ref())
                .cloned();
            new_server_slots.push(reusable.unwrap_or_else(|| Arc::new(ServerSlot::new(server))));
        }

        let new_set = Arc::new(ServerSet::new(new_server_slots));
        for (operation, previous_name) in OperationKind::ALL
            .into_iter()
            .zip(previous_active_names.iter())
        {
            new_set
                .route(operation)
                .preserve_active_server(previous_name.as_deref(), &new_set.servers)
                .await;
        }

        {
            let runtime_policy = self.runtime_policy();
            let mut current = self
                .runtime
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *current = Arc::new(RuntimeRoutingSnapshot {
                server_set: Arc::clone(&new_set),
                proxy_downstream_obfuscation,
                admission: Arc::clone(&current.admission),
                runtime_policy,
            });
        }
        if materially_changed {
            self.availability.reset();
        }

        if new_set.server_count() == 0 {
            log::warn!("Reloaded an empty TACACS+ server set; waiting for configuration");
        } else {
            log::info!("Reloaded the TACACS+ server set: {} server(s)", new_set.server_count());
        }

        for stale in previous
            .servers
            .iter()
            .filter(|old| !new_set.servers.iter().any(|new| Arc::ptr_eq(old, new)))
        {
            stale.drain_cached_connection().await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use tacacsrs_config::keystore::SymmetricKeyInlineDefinition;
    use tacacsrs_config::{EpskSupportedHash, TacacsPlusServer, Tls13Epsk, TlsClientClientIdentity};
    use tokio::sync::Notify;

    use super::{BoundServer, UpstreamManager};
    use crate::config::{
        FailoverStrategy, OperationPolicies, ProxyDownstreamObfuscation, RuntimePolicy,
    };
    use crate::runtime::{REQUIRED_SERVER_TYPES, RuntimeHealthPublisher};
    use crate::EnabledServices;
    use crate::test_support::{FakeConnection, FakeConnector};
    use crate::upstream::UpstreamConnector;
    use crate::upstream::OperationKind;

    struct BlockingConnector {
        connection: Arc<FakeConnection>,
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl UpstreamConnector for BlockingConnector {
        async fn connect(
            &self,
            _server: Arc<TacacsPlusServer>,
            _operation: OperationKind,
        ) -> anyhow::Result<Arc<dyn crate::upstream::UpstreamConnection>> {
            self.started.notify_one();
            self.release.notified().await;
            Ok(Arc::clone(&self.connection) as Arc<dyn crate::upstream::UpstreamConnection>)
        }
    }

    fn test_server(address: &str) -> TacacsPlusServer {
        let (host, port) = match address.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(49)),
            None => (address.to_owned(), 49),
        };
        tacacsrs_config::TacacsPlusServer {
            name: address.to_owned(),
            server_type: REQUIRED_SERVER_TYPES,
            address: host,
            port,
            shared_secret: None,
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

    fn materialized_server(secret: &[u8]) -> TacacsPlusServer {
        let mut server = test_server("192.0.2.70:449");
        server.name = "rotation-test".to_owned();
        server.client_identity = Some(TlsClientClientIdentity {
            credentials_reference: None,
            certificate: None,
            tls13_epsk: Some(Tls13Epsk {
                inline_definition: Some(SymmetricKeyInlineDefinition {
                    key_format: None,
                    cleartext_symmetric_key: Some(tacacsrs_secrets::SecretBytes::new(
                        secret.to_vec(),
                    )),
                }),
                central_keystore_reference: None,
                external_identity: "client".to_owned(),
                hash: EpskSupportedHash::Sha256,
                context: None,
                target_protocol: None,
                target_kdf: None,
                psk_dhe_ke_groups: Vec::new(),
            }),
        });
        server
    }

    fn bound_secret(bound: &BoundServer) -> &[u8] {
        bound
            .server()
            .client_identity
            .as_ref()
            .and_then(|identity| identity.tls13_epsk.as_ref())
            .and_then(|epsk| epsk.inline_definition.as_ref())
            .and_then(|inline| inline.cleartext_symmetric_key.as_ref())
            .expect("the shared secret must be resolved")
            .expose_secret()
    }

    #[test]
    fn materialized_secret_changes_generated_server_equality() {
        let first = materialized_server(b"first-secret-material");
        let replacement = materialized_server(b"replacement-secret");
        assert_ne!(first, replacement);
    }

    #[test]
    fn inline_shared_secret_change_prevents_runtime_server_reuse() {
        let mut first = test_server("192.0.2.70:49");
        first.shared_secret = Some(tacacsrs_secrets::SecretString::new("first-secret".to_owned()));
        let same = first.clone();

        let mut replacement = test_server("192.0.2.70:49");
        replacement.shared_secret =
            Some(tacacsrs_secrets::SecretString::new("replacement-secret".to_owned()));
        assert_eq!(first, same);
        assert_ne!(first, replacement);
    }

    #[tokio::test]
    async fn resolved_rotation_replaces_new_bindings_and_preserves_existing_snapshots() {
        let first = Arc::new(materialized_server(b"first-secret-material"));
        let second = Arc::new(materialized_server(b"second-secret-material"));
        let rollback = Arc::new(materialized_server(b"first-secret-material"));
        let connection = Arc::new(FakeConnection {
            address: "192.0.2.70:449".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            connection.address.clone(),
            Arc::clone(&connection),
        )])));
        let state = UpstreamManager::new_shared(
            vec![Arc::clone(&first)],
            connector,
            Duration::from_secs(1),
            test_health(),
        );

        let first_binding = state
            .bind_server_for_new_session()
            .await
            .expect("the first server must bind");
        state
            .reload_shared_servers(vec![second])
            .await
            .expect("the replacement server must apply");
        connection.usable.store(true, Ordering::Relaxed);
        let second_binding = state
            .bind_server_for_new_session()
            .await
            .expect("the replacement server must bind");
        state
            .reload_shared_servers(vec![rollback])
            .await
            .expect("the first server must apply again");
        connection.usable.store(true, Ordering::Relaxed);
        let rollback_binding = state
            .bind_server_for_new_session()
            .await
            .expect("the restored server must bind");

        assert_eq!(bound_secret(&first_binding), b"first-secret-material");
        assert_eq!(bound_secret(&second_binding), b"second-secret-material");
        assert_eq!(bound_secret(&rollback_binding), b"first-secret-material");
        assert_eq!(bound_secret(&first_binding), b"first-secret-material");
    }

    #[tokio::test]
    async fn proxy_binding_uses_server_and_obfuscation_from_one_runtime_generation() {
        let first = Arc::new(test_server("192.0.2.70:49"));
        let second = Arc::new(test_server("192.0.2.71:49"));
        let connection = Arc::new(FakeConnection {
            address: "192.0.2.70:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let connector = Arc::new(BlockingConnector {
            connection,
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        });
        let first_policy = ProxyDownstreamObfuscation::SharedSecret(
            tacacsrs_secrets::SecretString::new("first-proxy-secret".to_owned()),
        );
        let second_policy = ProxyDownstreamObfuscation::SharedSecret(
            tacacsrs_secrets::SecretString::new("second-proxy-secret".to_owned()),
        );
        let state = Arc::new(UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
            vec![first],
            first_policy.clone(),
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                Duration::from_secs(1),
            )
            .expect("test runtime policy"),
            connector,
            test_health(),
        ));

        let binding = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                state
                    .bind_proxy_server_for_new_session(OperationKind::Accounting)
                    .await
            })
        };
        started.notified().await;
        state
            .reload_shared_servers_with_proxy_downstream_obfuscation(
                vec![second],
                second_policy.clone(),
            )
            .await
            .expect("the replacement runtime generation must publish");
        release.notify_one();

        let (bound_server, bound_policy) = binding
            .await
            .expect("the binding task must stop")
            .expect("the proxy server must bind");
        assert_eq!(bound_server.server().address, "192.0.2.70");
        assert_eq!(bound_policy, first_policy);
        assert_eq!(state.proxy_transport_settings().downstream_obfuscation(), &second_policy);
    }

    fn test_health() -> RuntimeHealthPublisher {
        RuntimeHealthPublisher::new(EnabledServices::CLIENT_API)
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn test_server_selection_wraps_to_later_server() {
        let first = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let second = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let third = Arc::new(FakeConnection {
            address: "server-c:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (first.address.clone(), Arc::clone(&first)),
            (second.address.clone(), Arc::clone(&second)),
            (third.address.clone(), Arc::clone(&third)),
        ])));

        let state = UpstreamManager::new(
            vec![
                test_server("server-a:49"),
                test_server("server-b:49"),
                test_server("server-c:49"),
            ],
            connector,
            Duration::from_millis(25),
            test_health(),
        );

        let bound = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(bound.connection.server_address(), "server-c:49");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn test_connections_open_lazily_in_preference_order() {
        let first = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let second = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let third = Arc::new(FakeConnection {
            address: "server-c:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (first.address.clone(), Arc::clone(&first)),
            (second.address.clone(), Arc::clone(&second)),
            (third.address.clone(), Arc::clone(&third)),
        ])));

        let state = UpstreamManager::new(
            vec![
                test_server("server-a:49"),
                test_server("server-b:49"),
                test_server("server-c:49"),
            ],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(25),
            test_health(),
        );

        state.warm_connections();

        assert_eq!(connector.connect_attempts_for(&first.address).await, 0);
        assert_eq!(connector.connect_attempts_for(&second.address).await, 0);
        assert_eq!(connector.connect_attempts_for(&third.address).await, 0);

        let bound = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(bound.connection.server_address(), second.address);
        assert_eq!(connector.connect_attempts_for(&first.address).await, 1);
        assert_eq!(connector.connect_attempts_for(&second.address).await, 1);
    }

    #[tokio::test]
    async fn operation_failure_does_not_move_other_operation_cursors() {
        let primary = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let backup = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (primary.address.clone(), Arc::clone(&primary)),
            (backup.address.clone(), Arc::clone(&backup)),
        ])));
        let state = UpstreamManager::new(
            vec![test_server("server-a:49"), test_server("server-b:49")],
            connector,
            Duration::from_secs(30),
            test_health(),
        );

        let authentication = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("primary authentication route");
        state.note_bound_server_failure(&authentication).await;
        primary.usable.store(true, Ordering::Release);

        let authorization = state
            .bind_server_for_operation(OperationKind::Authorization)
            .await
            .expect("authorization route remains on primary");
        let failed_over_authentication = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("authentication route uses backup");

        assert_eq!(authorization.connection.server_address(), primary.address);
        assert_eq!(failed_over_authentication.connection.server_address(), backup.address);
    }

    #[tokio::test(start_paused = true)]
    async fn real_request_recovers_a_higher_priority_operation_route() {
        let primary = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let backup = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (primary.address.clone(), Arc::clone(&primary)),
            (backup.address.clone(), Arc::clone(&backup)),
        ])));
        let state = UpstreamManager::new(
            vec![test_server("server-a:49"), test_server("server-b:49")],
            connector,
            Duration::from_secs(5),
            test_health(),
        );

        let initial = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("initial primary route");
        state.note_bound_server_failure(&initial).await;
        primary.usable.store(true, Ordering::Release);
        let fallback = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("fallback route");
        assert_eq!(fallback.connection.server_address(), backup.address);

        tokio::time::advance(Duration::from_secs(5)).await;
        let recovery = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("recovery trial");
        assert_eq!(recovery.connection.server_address(), primary.address);
        state.note_bound_server_success(&recovery).await;

        let restored = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("restored primary route");
        assert_eq!(restored.connection.server_address(), primary.address);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_failure_does_not_invalidate_a_recovered_connection() {
        let primary = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            primary.address.clone(),
            Arc::clone(&primary),
        )])));
        let state = UpstreamManager::new(
            vec![test_server("server-a:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_secs(5),
            test_health(),
        );

        let stale_binding = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("initial binding");
        state.note_bound_server_failure(&stale_binding).await;
        primary.usable.store(true, Ordering::Release);
        tokio::time::advance(Duration::from_secs(5)).await;
        let recovered = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("recovered binding");
        state.note_bound_server_success(&recovered).await;

        state.note_bound_server_failure(&stale_binding).await;
        let current = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .expect("current connection remains available");

        assert_eq!(current.connection_generation, recovered.connection_generation);
        assert_eq!(connector.connect_attempts_for(&primary.address).await, 2);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn reload_preserves_unchanged_cached_connection() {
        let first = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let second = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (first.address.clone(), Arc::clone(&first)),
            (second.address.clone(), Arc::clone(&second)),
        ])));

        let state = UpstreamManager::new(
            vec![test_server("server-a:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(25),
            test_health(),
        );

        let initial = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(initial.connection.server_address(), first.address);
        assert_eq!(connector.connect_attempts_for(&first.address).await, 1);

        state
            .reload_servers(vec![test_server("server-a:49"), test_server("server-b:49")])
            .await
            .unwrap();

        let bound = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(bound.connection.server_address(), first.address);
        assert_eq!(connector.connect_attempts_for(&first.address).await, 1);
        assert_eq!(connector.connect_attempts_for(&second.address).await, 0);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn reload_drops_removed_or_modified_cached_connection() {
        let first = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let second = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (first.address.clone(), Arc::clone(&first)),
            (second.address.clone(), Arc::clone(&second)),
        ])));

        let state = UpstreamManager::new(
            vec![test_server("server-a:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(25),
            test_health(),
        );

        let initial = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(initial.connection.server_address(), first.address);
        assert_eq!(connector.connect_attempts_for(&first.address).await, 1);

        let mut modified = test_server("server-a:49");
        modified.timeout = 10;
        state
            .reload_servers(vec![modified, test_server("server-b:49")])
            .await
            .unwrap();

        let bound = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(bound.connection.server_address(), second.address);
        assert_eq!(connector.connect_attempts_for(&first.address).await, 2);
        assert!(!first.usable.load(Ordering::Relaxed));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio synchronization.
    async fn aggregate_exhaustion_marks_upstreams_unavailable() {
        let first = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let second = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (first.address.clone(), first),
            (second.address.clone(), second),
        ])));
        let health = test_health();
        let state = UpstreamManager::new(
            vec![test_server("server-a:49"), test_server("server-b:49")],
            connector,
            Duration::from_millis(25),
            health.clone(),
        );

        let result = state.bind_server_for_new_session().await;

        assert!(result.is_err());
        assert_eq!(
            health.snapshot().upstream_availability(),
            crate::UpstreamAvailability::Unavailable,
        );
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&crate::DegradationReason::UpstreamsUnavailable));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio synchronization.
    async fn material_server_reload_resets_availability_to_unknown() {
        let connection = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector =
            Arc::new(FakeConnector::new(HashMap::from([(connection.address.clone(), connection)])));
        let health = test_health();
        let state = UpstreamManager::new(
            vec![test_server("server-a:49")],
            connector,
            Duration::from_millis(25),
            health.clone(),
        );
        state
            .bind_server_for_new_session()
            .await
            .expect("the server must bind");
        assert_eq!(
            health.snapshot().upstream_availability(),
            crate::UpstreamAvailability::Available,
        );

        state
            .reload_servers(vec![test_server("server-a:49"), test_server("server-b:49")])
            .await
            .expect("the reload must succeed");

        assert_eq!(health.snapshot().upstream_availability(), crate::UpstreamAvailability::Unknown,);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn test_concurrent_failover_coalesces_connection_attempts() {
        let first = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let second = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(
            FakeConnector::new(HashMap::from([
                (first.address.clone(), Arc::clone(&first)),
                (second.address.clone(), Arc::clone(&second)),
            ]))
            .with_connect_delay(Duration::from_millis(25)),
        );

        let state = Arc::new(UpstreamManager::new(
            vec![test_server("server-a:49"), test_server("server-b:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
            test_health(),
        ));

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let state = Arc::clone(&state);
            tasks.push(tokio::spawn(async move {
                let bound = state.bind_server_for_new_session().await.unwrap();
                bound.connection.server_address().to_owned()
            }));
        }

        for task in tasks {
            assert_eq!(task.await.unwrap(), second.address);
        }

        assert_eq!(connector.connect_attempts_for(&first.address).await, 1);
        assert_eq!(connector.connect_attempts_for(&second.address).await, 1);
        assert_eq!(connector.max_in_flight_connects(), 1);
    }
}
