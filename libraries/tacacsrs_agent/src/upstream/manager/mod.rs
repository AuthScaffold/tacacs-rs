//! Publishes prepared catalogs with service policy, admission, and health.
//!
//! Networking owns route selection, circuits, cached connections, and reconnect
//! serialization. The manager retains source metadata and projects YANG inputs.

use std::sync::{Arc, RwLock as StdRwLock};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_config::prepare::PrepareOptions;
use tacacsrs_networking::routed::EndpointConnector;

use self::availability::PublicationController;
use self::server_set::{RuntimeRoutingSnapshot, ServerSet};
use self::prepared_server::PreparedServer;
use crate::config::{PreparedProxyPolicy, RuntimePolicy};
#[cfg(test)]
use crate::config::{FailoverStrategy, OperationPolicies};
use crate::runtime::RuntimeHealthPublisher;
use crate::upstream::admission::AdmissionRegistry;
use crate::upstream::{AdmissionError, OperationKind, ProxyTransportSettings};
#[cfg(test)]
use crate::upstream::UpstreamConnector;

pub(crate) use self::server_set::{BoundServer, RoutingLease};
#[cfg(test)]
pub(crate) use self::server_set::ServiceConnector;

mod server_set;
mod prepared_server;
mod availability;
mod binding;

/// Publishes catalogs and captures request policy for both local services.
///
/// Networking supplies the binding and records routing outcomes. This adapter
/// associates that binding with source metadata and generation-aware health.
pub(crate) struct UpstreamManager<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    closed: std::sync::atomic::AtomicBool,
    reload_lock: tokio::sync::Mutex<()>,
    /// Current immutable routing generation for new requests.
    runtime: StdRwLock<Arc<RuntimeRoutingSnapshot<Connector>>>,
    connect_options: PrepareOptions,
    /// Serializes generation publication and server-availability observations.
    publication: PublicationController,
    #[cfg(test)]
    publication_pause: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
}

#[cfg(test)]
impl UpstreamManager<ServiceConnector> {
    /// Creates shared failover state for the service runtime.
    ///
    /// The runtime can start without a configured server while it waits for
    /// external configuration. In this state, IPC requests immediately return
    /// a retriable configuration error.
    #[cfg(test)]
    pub(crate) fn new(
        servers: Vec<TacacsPlusServer>,
        connector: Arc<UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        let servers = servers.into_iter().map(Arc::new).collect();
        Self::new_shared_with_proxy_downstream_obfuscation(
            servers,
            PreparedProxyPolicy::unobfuscated(),
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                preferred_probe_interval,
            )
            .expect("test recovery interval must be nonzero"),
            connector,
            health,
            PrepareOptions::default(),
        )
        .expect("test endpoints must prepare")
    }

    #[cfg(test)]
    pub(crate) fn new_shared(
        servers: Vec<Arc<TacacsPlusServer>>,
        connector: Arc<UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        Self::new_shared_with_proxy_downstream_obfuscation(
            servers,
            PreparedProxyPolicy::unobfuscated(),
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                preferred_probe_interval,
            )
            .expect("test recovery interval must be nonzero"),
            connector,
            health,
            PrepareOptions::default(),
        )
        .expect("test endpoints must prepare")
    }

    pub(crate) fn new_shared_with_proxy_downstream_obfuscation(
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        runtime_policy: RuntimePolicy,
        connector: Arc<UpstreamConnector>,
        health: RuntimeHealthPublisher,
        connect_options: PrepareOptions,
    ) -> anyhow::Result<Self> {
        Self::from_connector(
            servers,
            proxy_downstream_obfuscation,
            runtime_policy,
            ServiceConnector(connector),
            health,
            connect_options,
        )
    }
}

impl<Connector: EndpointConnector> UpstreamManager<Connector> {
    pub(crate) fn from_connector(
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        runtime_policy: RuntimePolicy,
        connector: Connector,
        health: RuntimeHealthPublisher,
        connect_options: PrepareOptions,
    ) -> anyhow::Result<Self> {
        let servers = servers
            .into_iter()
            .map(|server| PreparedServer::new(server, connect_options).map(Arc::new))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let credential_lifetime = servers
            .iter()
            .try_fold(crate::runtime::CredentialLifetime::unbounded(), |lifetime, server| {
                lifetime.intersect(server.certificate_lifetime)
            })?;
        let server_set = Arc::new(ServerSet::new(servers, connector));
        Ok(Self {
            closed: std::sync::atomic::AtomicBool::new(false),
            reload_lock: tokio::sync::Mutex::new(()),
            runtime: StdRwLock::new(Arc::new(RuntimeRoutingSnapshot {
                generation: 0,
                availability_generation: 0,
                server_set,
                proxy_downstream_obfuscation,
                admission: Arc::new(AdmissionRegistry::new(&runtime_policy)),
                runtime_policy: Arc::new(runtime_policy),
                credential_lifetime,
            })),
            connect_options,
            publication: PublicationController::new(health),
            #[cfg(test)]
            publication_pause: std::sync::Mutex::new(None),
        })
    }

    fn current_runtime(&self) -> Arc<RuntimeRoutingSnapshot<Connector>> {
        Arc::clone(
            &self
                .runtime
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub(crate) fn retirement_deadline(
        &self,
    ) -> anyhow::Result<tacacsrs_networking::RequestDeadline> {
        let runtime = self.current_runtime();
        let budget = OperationKind::ALL
            .into_iter()
            .map(|operation| runtime.runtime_policy.limits(operation).request_timeout())
            .max()
            .unwrap_or_default();
        tacacsrs_networking::RequestDeadline::after(budget)
    }

    pub(crate) fn ensure_open(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "The TACACS+ service is closed"
        );
        Ok(())
    }

    pub(crate) fn shutdown_timeout(&self) -> std::time::Duration {
        self.current_runtime().runtime_policy.shutdown_timeout()
    }

    pub(crate) fn source_stale_timeout(&self) -> std::time::Duration {
        self.current_runtime().runtime_policy.source_stale_timeout()
    }

    pub(crate) fn credential_stale_timeout(&self) -> std::time::Duration {
        self.current_runtime()
            .runtime_policy
            .credential_stale_timeout()
    }

    pub(crate) fn credential_refresh_interval(&self) -> std::time::Duration {
        self.current_runtime()
            .runtime_policy
            .credential_refresh_interval()
    }

    pub(crate) fn shutdown_deadline(&self) -> anyhow::Result<tacacsrs_networking::RequestDeadline> {
        let runtime = self.current_runtime();
        let requests = OperationKind::ALL
            .into_iter()
            .map(|operation| runtime.runtime_policy.limits(operation).request_timeout())
            .max()
            .unwrap_or_default();
        tacacsrs_networking::RequestDeadline::after(
            requests.min(runtime.runtime_policy.shutdown_timeout()),
        )
    }

    pub(crate) fn close(&self) {
        let runtime = self
            .runtime
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        runtime.admission.close();
        runtime.server_set.client.close();
    }

    pub(crate) fn cancel(&self) {
        self.close();
        self.current_server_set().client.cancel();
    }

    pub(crate) async fn close_and_join(
        &self,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.close();
        self.current_server_set()
            .client
            .close_and_join(deadline)
            .await
    }

    fn current_server_set(&self) -> Arc<ServerSet<Connector>> {
        Arc::clone(&self.current_runtime().server_set)
    }

    pub(in crate::upstream) fn capture_request(
        &self,
        service: crate::config::PolicyService,
        operation: OperationKind,
    ) -> RoutingLease<Connector> {
        let lease = RoutingLease::new(self.current_runtime(), service, operation);
        log::debug!(
            "Captured {} request routing generation {}",
            operation.name(),
            lease.generation()
        );
        lease
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

    /// Atomically replaces the runtime policy for new requests.
    #[cfg(test)]
    pub(crate) fn reload_runtime_policy(&self, runtime_policy: RuntimePolicy) -> bool {
        self.admit_policy()
            .and_then(|revision| self.publish_policy(revision, runtime_policy))
            .is_ok_and(|outcome| matches!(outcome, crate::PolicyUpdate::Applied(_)))
    }

    pub(crate) fn admit_policy(&self) -> anyhow::Result<crate::PolicyRevision> {
        let _runtime = self
            .runtime
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_open()?;
        Ok(self.publication.admit_policy())
    }

    pub(crate) fn reject_policy(
        &self,
        revision: crate::PolicyRevision,
    ) -> anyhow::Result<crate::PolicyUpdate> {
        let _runtime = self
            .runtime
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_open()?;
        Ok(self.publication.reject_policy(revision))
    }

    pub(crate) fn publish_policy(
        &self,
        revision: crate::PolicyRevision,
        runtime_policy: RuntimePolicy,
    ) -> anyhow::Result<crate::PolicyUpdate> {
        let mut current = self
            .runtime
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_open()?;
        let generation = current.generation.wrapping_add(1);
        Ok(self.publication.publish_policy(revision, generation, || {
            current.admission.update(&runtime_policy);
            *current = Arc::new(RuntimeRoutingSnapshot {
                generation,
                availability_generation: current.availability_generation,
                server_set: Arc::clone(&current.server_set),
                proxy_downstream_obfuscation: current.proxy_downstream_obfuscation.clone(),
                admission: Arc::clone(&current.admission),
                runtime_policy: Arc::new(runtime_policy),
                credential_lifetime: current.credential_lifetime,
            });
        }))
    }

    pub(crate) fn publish_initial_health(&self, applied: bool) {
        let current = self
            .runtime
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.publication.publish_runtime(
            current.generation,
            current.server_set.server_count(),
            Some(applied),
            false,
            |_| None,
        );
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
    #[cfg(test)]
    pub(crate) fn eligible_server_count(&self, operation: OperationKind) -> usize {
        self.current_server_set().client.eligible_count(operation)
    }

    /// Waits for shared operation capacity with the captured request inputs.
    ///
    /// Services reach this through [`crate::upstream::OperationRouter`].
    pub(in crate::upstream) async fn admit_request(
        &self,
        lease: &RoutingLease<Connector>,
        body_length: usize,
    ) -> Result<crate::upstream::AdmissionPermit, AdmissionError> {
        let reservation = Self::reserve_request(lease, body_length)?;
        self.admit_reserved(lease, reservation).await
    }

    pub(in crate::upstream) fn reserve_request(
        lease: &RoutingLease<Connector>,
        body_length: usize,
    ) -> Result<tacacsrs_networking::admission::AdmissionReservation, AdmissionError> {
        lease.validate_body_length(body_length)?;
        let runtime = &lease.runtime;
        let operation = lease.operation;
        if runtime.server_set.client.eligible_count(operation) == 0 {
            return Err(AdmissionError::NoEligibleServer { operation });
        }
        runtime.admission.reserve(operation, lease.deadline())
    }

    pub(in crate::upstream) async fn admit_reserved(
        &self,
        lease: &RoutingLease<Connector>,
        reservation: tacacsrs_networking::admission::AdmissionReservation,
    ) -> Result<crate::upstream::AdmissionPermit, AdmissionError> {
        let runtime = &lease.runtime;
        let operation = lease.operation;
        let wait_timeout = runtime
            .server_set
            .client
            .active_endpoint(operation)
            .await
            .and_then(|endpoint| endpoint.prepared().connection_timeout())
            .unwrap_or(std::time::Duration::ZERO);
        reservation
            .wait_until(lease.deadline().capped(wait_timeout))
            .await
            .map_err(|error| match error {
                tacacsrs_networking::admission::AdmissionError::Closed => AdmissionError::Closed,
                _ => AdmissionError::CapacityTimeout { wait_timeout },
            })
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
        proxy_downstream_obfuscation: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        self.reload_shared_servers_with_commit(servers, proxy_downstream_obfuscation, || None)
            .await
    }

    /// Commits caller bookkeeping with the catalog, before health readers see it.
    /// The callback must not block, fail, or acquire runtime or health locks.
    pub(crate) async fn reload_shared_servers_with_commit(
        &self,
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        commit: impl FnOnce() -> Option<crate::runtime::MaterializationCommit> + Send,
    ) -> anyhow::Result<()> {
        self.reload_shared_servers_with_retirement(
            servers,
            proxy_downstream_obfuscation,
            None,
            None,
            commit,
        )
        .await
    }

    pub(crate) async fn reload_shared_servers_with_retirement(
        &self,
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        retirement: Option<tacacsrs_networking::RequestDeadline>,
        validity: Option<crate::runtime::CredentialLifetime>,
        commit: impl FnOnce() -> Option<crate::runtime::MaterializationCommit> + Send,
    ) -> anyhow::Result<()> {
        let _reload = self.reload_lock.lock().await;
        anyhow::ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "The TACACS+ service is closed"
        );
        let retirement_deadline = retirement.unwrap_or(self.retirement_deadline()?);
        let previous = self.current_server_set();
        let materially_changed = previous.server_count() != servers.len()
            || previous
                .servers
                .iter()
                .zip(&servers)
                .any(|(old, new)| old.server.as_ref() != new.as_ref());
        let mut new_server_slots = Vec::with_capacity(servers.len());
        for server in servers {
            let reusable = previous
                .servers
                .iter()
                .find(|state| state.server.as_ref() == server.as_ref())
                .cloned();
            let slot = match reusable {
                Some(slot) => slot,
                None => Arc::new(PreparedServer::new(server, self.connect_options)?),
            };
            new_server_slots.push(slot);
        }

        let validity = new_server_slots.iter().try_fold(
            validity.unwrap_or(crate::runtime::CredentialLifetime::unbounded()),
            |lifetime, server| lifetime.intersect(server.certificate_lifetime),
        )?;

        let client = previous
            .client
            .with_endpoints(
                new_server_slots
                    .iter()
                    .map(|server| server.endpoint.clone())
                    .collect(),
            )
            .await;
        let new_set = Arc::new(ServerSet {
            servers: new_server_slots,
            client,
        });
        let urgent = previous.changed_crl_servers(&new_set);

        {
            let mut current = self
                .runtime
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            anyhow::ensure!(
                !self.closed.load(std::sync::atomic::Ordering::Acquire),
                "The TACACS+ service closed during preparation"
            );
            anyhow::ensure!(validity.is_valid(), "Credential validity expired before publication");
            let generation = current.generation.wrapping_add(1);
            previous.retire_replaced_until(&new_set, retirement_deadline, &urgent);
            self.publication.publish_runtime(
                generation,
                new_set.server_count(),
                Some(true),
                materially_changed,
                |availability_generation| {
                    *current = Arc::new(RuntimeRoutingSnapshot {
                        generation,
                        availability_generation,
                        server_set: Arc::clone(&new_set),
                        proxy_downstream_obfuscation,
                        admission: Arc::clone(&current.admission),
                        runtime_policy: Arc::clone(&current.runtime_policy),
                        credential_lifetime: validity,
                    });
                    let mut materialization = commit();
                    if let Some(commit) = &mut materialization {
                        if commit.expired == crate::runtime::ExpiredMaterial::None {
                            commit.validity = validity;
                        }
                    }
                    materialization
                },
            );
        }

        if new_set.server_count() == 0 {
            log::warn!("Reloaded an empty TACACS+ server set; waiting for configuration");
        } else {
            log::info!("Reloaded the TACACS+ server set: {} server(s)", new_set.server_count());
        }

        #[cfg(test)]
        {
            let pause = self.publication_pause.lock().unwrap().take();
            if let Some(pause) = pause {
                pause.notified().await;
            }
        }
        previous.client.retire_replaced(&new_set.client).await;

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn pause_next_publication(&self) -> Arc<tokio::sync::Notify> {
        let pause = Arc::new(tokio::sync::Notify::new());
        *self.publication_pause.lock().unwrap() = Some(pause.clone());
        pause
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
    use crate::config::{FailoverStrategy, OperationPolicies, PreparedProxyPolicy, RuntimePolicy};
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
    impl tacacsrs_networking::routed::EndpointConnector for BlockingConnector {
        type Connection = dyn crate::upstream::UpstreamConnection;

        async fn retire(&self, connection: &Self::Connection) {
            connection.stop_accepting_new_sessions().await;
        }
        fn close(&self, connection: &Self::Connection) {
            connection.close();
        }
        async fn close_and_join(
            &self,
            connection: &Self::Connection,
            deadline: tacacsrs_networking::RequestDeadline,
        ) -> anyhow::Result<()> {
            connection.close_and_join(deadline).await
        }

        async fn connect(
            &self,
            _endpoint: tacacsrs_networking::PreparedEndpoint,
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

    fn bound_secret(bound: &BoundServer<super::ServiceConnector>) -> &[u8] {
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

    #[tokio::test]
    async fn failed_preparation_keeps_routes_policy_and_cached_connections() {
        let server = test_server("192.0.2.70:49");
        let connection = Arc::new(FakeConnection {
            address: "192.0.2.70:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            connection.address.clone(),
            Arc::clone(&connection),
        )])));
        let state = UpstreamManager::new(
            vec![server.clone()],
            connector.clone(),
            Duration::from_secs(1),
            test_health(),
        );
        let bound = state.bind_server_for_new_session().await.unwrap();
        let previous = state.current_runtime();
        let mut changed = server.clone();
        changed.timeout = 9;
        let invalid = tacacsrs_config::TacacsPlusServerBuilder::new(
            "invalid",
            REQUIRED_SERVER_TYPES,
            "192.0.2.71",
            449,
        )
        .with_tls13_epsk_psk_only("client", b"short".to_vec())
        .build();
        assert!(state
            .reload_shared_servers_with_proxy_downstream_obfuscation(
                vec![Arc::new(changed), Arc::new(invalid)],
                PreparedProxyPolicy::unobfuscated(),
            )
            .await
            .is_err());
        assert!(Arc::ptr_eq(&previous, &state.current_runtime()));
        assert!(connection.usable.load(Ordering::Relaxed));
        let current = state.bind_server_for_new_session().await.unwrap();
        assert!(Arc::ptr_eq(&bound.connection, &current.connection));
        assert_eq!(connector.connect_attempts_for("192.0.2.70:49").await, 1);

        state.reload_servers(vec![server]).await.unwrap();
        assert!(Arc::ptr_eq(
            &previous.server_set.servers[0],
            &state.current_runtime().server_set.servers[0]
        ));
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
        let prepare = |secret: &str| {
            tacacsrs_config::proxy_policy::prepare_proxy_policy(
                &tacacsrs_config::tacacsrs::LocalServices {
                    tacacs_proxy_enabled: true,
                    proxy_credential_source:
                        tacacsrs_config::tacacsrs::ProxyCredentialSource::Inline,
                    proxy_shared_secret: Some(tacacsrs_secrets::SecretString::new(
                        secret.to_owned(),
                    )),
                    ..Default::default()
                },
                None,
            )
            .unwrap()
        };
        let first_policy = prepare("first-proxy-secret");
        let second_policy = prepare("second-proxy-secret");
        let state = Arc::new(
            UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
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
                tacacsrs_config::prepare::PrepareOptions::default(),
            )
            .expect("test endpoints must prepare"),
        );

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
            Arc::clone(&connector) as Arc<UpstreamConnector>,
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
    async fn credential_validity_bounds_leases_and_rechecks_waiting_publication() {
        use crate::config::PolicyService;
        use crate::runtime::CredentialLifetime;
        use tacacsrs_credential_resolution::CredentialValidity;
        let connection = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let state = UpstreamManager::new(
            vec![test_server("server-a:49")],
            Arc::new(FakeConnector::new(HashMap::from([(
                connection.address.clone(),
                connection.clone(),
            )]))),
            Duration::from_secs(30),
            test_health(),
        );
        let lifetime = CredentialLifetime::new(
            CredentialValidity::new(
                None,
                Some(std::time::SystemTime::now() + Duration::from_secs(2)),
            )
            .unwrap(),
        )
        .unwrap();
        state
            .reload_shared_servers_with_retirement(
                vec![Arc::new(test_server("server-a:49"))],
                PreparedProxyPolicy::unobfuscated(),
                None,
                Some(lifetime),
                || None,
            )
            .await
            .unwrap();
        let captured = state.capture_request(PolicyService::ClientApi, OperationKind::Accounting);
        assert_eq!(captured.deadline().expires_at(), lifetime.deadline.unwrap());
        state.bind_request(&captured).await.unwrap();
        let generation = state.current_runtime().generation;
        let guard = state.reload_lock.lock().await;
        let pending = state.reload_shared_servers_with_retirement(
            vec![Arc::new(test_server("server-a:49"))],
            PreparedProxyPolicy::unobfuscated(),
            None,
            Some(lifetime),
            || None,
        );
        tokio::pin!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(state.bind_request(&captured).await.is_err());
        let current = state.capture_request(PolicyService::ClientApi, OperationKind::Accounting);
        assert!(state.bind_request(&current).await.is_err());
        drop(guard);
        assert!(pending.await.is_err());
        assert_eq!(state.current_runtime().generation, generation);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_wakes_admission_and_rejects_reload_and_captured_routes() {
        use crate::config::{PolicyService, RequestLimits};
        use crate::upstream::AdmissionError;

        let connection = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let state = UpstreamManager::new(
            vec![test_server("server-a:49")],
            Arc::new(FakeConnector::new(HashMap::from([(
                connection.address.clone(),
                connection.clone(),
            )]))),
            Duration::from_secs(30),
            test_health(),
        );
        let limits = RequestLimits::new(1024, 1).unwrap();
        state.reload_runtime_policy(
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::new(limits, limits, limits),
                Duration::from_secs(30),
            )
            .unwrap(),
        );
        let lease = state.capture_request(PolicyService::ClientApi, OperationKind::Accounting);
        let _active = state.admit_request(&lease, 1).await.unwrap();
        let _bound = state.bind_request(&lease).await.unwrap();
        let pending = state.admit_request(&lease, 1);
        tokio::pin!(pending);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        state
            .close_and_join(tacacsrs_networking::RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        assert!(matches!(pending.await, Err(AdmissionError::Closed)));
        assert!(state.bind_request(&lease).await.is_err());
        assert!(state
            .reload_servers(vec![test_server("server-b:49")])
            .await
            .is_err());
        assert!(!connection.usable.load(Ordering::Acquire));
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_cancels_connection_setup_and_releases_reconnect_lock() {
        use crate::config::RequestLimits;

        let release = Arc::new(Notify::new());
        let connector = Arc::new(BlockingConnector {
            connection: Arc::new(FakeConnection {
                address: "server-a:49".to_owned(),
                usable: AtomicBool::new(true),
                fail_next_request: AtomicBool::new(false),
            }),
            started: Arc::new(Notify::new()),
            release: release.clone(),
        });
        let health = test_health();
        let state = UpstreamManager::new(
            vec![test_server("server-a:49")],
            connector,
            Duration::from_secs(30),
            health.clone(),
        );
        let limits = RequestLimits::new(1024, 1)
            .unwrap()
            .with_request_timeout(Duration::from_secs(1))
            .unwrap();
        state.reload_runtime_policy(
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::new(limits, limits, limits),
                Duration::from_secs(30),
            )
            .unwrap(),
        );
        let started = tokio::time::Instant::now();
        let error = state.bind_server_for_new_session().await.err().unwrap();
        assert!(error.is::<tacacsrs_networking::DeadlineElapsed>());
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert_eq!(
            health.snapshot().upstream_availability(),
            crate::runtime::UpstreamAvailability::Unknown
        );
        release.notify_one();
        state.bind_server_for_new_session().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn immediate_retirement_blocks_old_bindings_without_replacing_admission() {
        let old = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let fresh = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (old.address.clone(), old.clone()),
            (fresh.address.clone(), fresh.clone()),
        ])));
        let state = UpstreamManager::new(
            vec![test_server("server-a:49")],
            connector,
            Duration::from_secs(30),
            test_health(),
        );
        let retained =
            state.capture_request(crate::PolicyService::ClientApi, OperationKind::Accounting);
        state.bind_request(&retained).await.unwrap();
        state
            .reload_shared_servers_with_retirement(
                Vec::new(),
                PreparedProxyPolicy::unobfuscated(),
                Some(tacacsrs_networking::RequestDeadline::at(tokio::time::Instant::now())),
                None,
                || None,
            )
            .await
            .unwrap();
        assert_eq!(state.server_count(), 0);
        assert!(!old.usable.load(Ordering::Acquire));
        assert!(state.bind_request(&retained).await.is_err());
        state
            .reload_servers(vec![test_server("server-b:49")])
            .await
            .unwrap();
        let restored =
            state.capture_request(crate::PolicyService::ClientApi, OperationKind::Accounting);
        assert!(Arc::ptr_eq(&retained.runtime.admission, &restored.runtime.admission));
        state.bind_request(&restored).await.unwrap();
        assert!(fresh.usable.load(Ordering::Acquire));
    }

    #[tokio::test(start_paused = true)]
    async fn captured_request_keeps_policy_while_admission_waits() {
        use crate::config::{PolicyService, RequestLimits};
        use crate::upstream::AdmissionError;

        for service in [PolicyService::ClientApi, PolicyService::TacacsProxy] {
            let connector = Arc::new(FakeConnector::new(
                ["server-a:49", "server-b:49"]
                    .into_iter()
                    .map(|address| {
                        (
                            address.to_owned(),
                            Arc::new(FakeConnection {
                                address: address.to_owned(),
                                usable: AtomicBool::new(true),
                                fail_next_request: AtomicBool::new(false),
                            }),
                        )
                    })
                    .collect(),
            ));
            let state = UpstreamManager::new(
                vec![test_server("server-a:49")],
                connector,
                Duration::from_secs(30),
                test_health(),
            );
            let policy = |body, capacity| {
                let limits = RequestLimits::new(body, capacity).unwrap();
                RuntimePolicy::new(
                    FailoverStrategy::default(),
                    FailoverStrategy::default(),
                    OperationPolicies::new(limits, limits, limits),
                    Duration::from_secs(30),
                )
                .unwrap()
            };
            state.reload_runtime_policy(policy(1024, 2));
            let captured = state.capture_request(service, OperationKind::Authentication);
            let first = state.admit_request(&captured, 1).await.unwrap();
            let second = state.admit_request(&captured, 1).await.unwrap();
            let waiting = state.admit_request(&captured, 768);
            tokio::pin!(waiting);
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(waiting.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;

            state
                .reload_servers(vec![test_server("server-b:49")])
                .await
                .unwrap();
            state.reload_runtime_policy(policy(512, 1));
            let current = state.capture_request(service, OperationKind::Authentication);
            assert_ne!(captured.generation(), current.generation());
            assert!(Arc::ptr_eq(&captured.runtime.admission, &current.runtime.admission));
            assert_ne!(captured.runtime.runtime_policy, current.runtime.runtime_policy);
            assert!(matches!(
                current.validate_body_length(768),
                Err(AdmissionError::BodyTooLarge { maximum: 512, .. })
            ));
            captured.validate_body_length(768).unwrap();

            drop(first);
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(waiting.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(second);
            let retained_permit = waiting.await.unwrap();
            let retained = state.bind_request(&captured).await.unwrap();
            assert_eq!(retained.connection.server_address(), "server-a:49");
            let replacement = state.bind_request(&current).await.unwrap();
            assert_eq!(replacement.connection.server_address(), "server-b:49");
            assert!(matches!(
                state.admit_request(&current, 1).await,
                Err(AdmissionError::CapacityTimeout { .. })
            ));
            drop(retained_permit);
            state.admit_request(&current, 1).await.unwrap();
        }
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

        let captured = state.capture_request(
            crate::config::PolicyService::ClientApi,
            OperationKind::Authentication,
        );
        state.reload_runtime_policy(
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                Duration::from_secs(60),
            )
            .unwrap(),
        );
        tokio::time::advance(Duration::from_secs(5)).await;
        let current = state
            .bind_server_for_operation(OperationKind::Authentication)
            .await
            .unwrap();
        assert_eq!(current.connection.server_address(), backup.address);
        let recovery = state.bind_request(&captured).await.expect("recovery trial");
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
            Arc::clone(&connector) as Arc<UpstreamConnector>,
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

        assert_eq!(
            current.binding.connection_generation(),
            recovered.binding.connection_generation()
        );
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
            Arc::clone(&connector) as Arc<UpstreamConnector>,
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
            Arc::clone(&connector) as Arc<UpstreamConnector>,
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
            Arc::clone(&connector) as Arc<UpstreamConnector>,
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
