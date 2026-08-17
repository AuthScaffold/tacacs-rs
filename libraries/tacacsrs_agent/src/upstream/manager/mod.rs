//! Internal service for upstream TACACS+ server selection and failover.
//!
//! All listener tasks share `UpstreamManager`. It owns the preferred server
//! index and cached server connections.
//!
//! # Concurrency model
//!
//! Multiple IPC handlers can call `UpstreamManager` at the same time. The
//! manager uses small lock scopes to reduce contention.
//!
//! | Lock | Scope | Purpose |
//! |------|-------|---------|
//! | `active_index` (`RwLock`) | Global | Current preferred server index |
//! | `connection` (`RwLock`) | Per-server | Cached server connection |
//! | `connect_lock` (`Mutex`) | Per-server | Serializes reconnect attempts |
//!
//! The `connect_lock` makes concurrent IPC handlers share one reconnect
//! attempt. It prevents duplicate TLS handshakes to one TACACS+ server.

use std::sync::{Arc, RwLock as StdRwLock};
use std::sync::atomic::Ordering;

use anyhow::bail;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};

use self::availability::AvailabilityTracker;
use self::server_set::{RuntimeRoutingSnapshot, ServerSet};
use self::server_slot::ServerSlot;
use crate::config::ProxyDownstreamObfuscation;
use crate::runtime::{REQUIRED_SERVER_TYPES, RuntimeHealthPublisher};
use crate::upstream::{UpstreamConnection, UpstreamConnector};

pub(crate) use self::server_set::BoundServer;

mod server_set;
mod server_slot;
mod availability;

/// Shared server state for all IPC request handlers.
///
/// Each IPC request uses this type to select a TACACS+ server. The request
/// handler runs the operation and records failures for later requests.
///
/// The state machine walks the server list from `active_index`. After a failure,
/// it moves to the next index. A background probe resets the index to `0` when
/// the preferred server recovers.
///
/// Each server in this state must support all TACACS+ operations that the agent
/// provides. Thus, the router can use one ordered list for authentication,
/// authorization, and accounting. Add separate catalogs here if the agent adds
/// operation-specific routing.
pub(crate) struct UpstreamManager {
    /// Current immutable routing generation for new requests.
    runtime: StdRwLock<Arc<RuntimeRoutingSnapshot>>,
    /// Factory for new server connections.
    connector: Arc<dyn UpstreamConnector>,
    /// Interval between preferred-server recovery probes.
    preferred_probe_interval: std::time::Duration,
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
            connector,
            preferred_probe_interval,
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
            connector,
            preferred_probe_interval,
            health,
        )
    }

    pub(crate) fn new_shared_with_proxy_downstream_obfuscation(
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: ProxyDownstreamObfuscation,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        debug_assert!(
            servers
                .iter()
                .all(|server| server.supports_server_type(REQUIRED_SERVER_TYPES)),
            "each server in UpstreamManager must support all required TACACS+ operations"
        );
        let servers = servers
            .into_iter()
            .map(ServerSlot::new)
            .map(Arc::new)
            .collect();
        let server_set = Arc::new(ServerSet::new(servers, 0));
        Self {
            runtime: StdRwLock::new(Arc::new(RuntimeRoutingSnapshot {
                server_set,
                proxy_downstream_obfuscation,
            })),
            connector,
            preferred_probe_interval,
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

    pub(crate) fn proxy_downstream_obfuscation(&self) -> ProxyDownstreamObfuscation {
        self.current_runtime().proxy_downstream_obfuscation.clone()
    }

    /// Tries to cache a connection to the first responsive server.
    ///
    /// This best-effort warm-up walks the server list until it caches one usable
    /// connection. It does not connect to all servers.
    ///
    /// If no server responds, the service still starts. IPC requests try the
    /// failover list again when necessary.
    pub(crate) async fn warm_connections(&self) {
        let server_set = self.current_server_set();
        if server_set.server_count() == 0 {
            log::warn!(
                "No configured TACACS+ server supports authentication, authorization, and accounting; waiting for configuration"
            );
            return;
        }
        let availability_attempt = self.availability.begin_attempt();
        let start_index = *server_set.active_index.read().await;

        for offset in 0..server_set.server_count() {
            let index = (start_index + offset) % server_set.server_count();
            match self.ensure_connection(&server_set.servers[index]).await {
                Ok(connection) => {
                    *server_set.active_index.write().await = index;
                    self.availability.available(availability_attempt);
                    log::info!("Warmed the server connection to {}", connection.server_address());
                    return;
                }
                Err(error) => {
                    log::warn!(
                        "Initial connection attempt to {} failed: {error}",
                        server_set.servers[index].socket_address()
                    );
                }
            }
        }

        log::warn!("No TACACS+ server responded during startup; requests will try again");
        self.availability.unavailable(availability_attempt);
    }

    /// Returns the number of configured TACACS+ servers.
    pub(crate) fn server_count(&self) -> usize {
        self.current_server_set().server_count()
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
        let proxy_downstream_obfuscation = self.proxy_downstream_obfuscation();
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
        let previous_active_name = if previous.server_count() == 0 {
            None
        } else {
            let active_index = *previous.active_index.read().await;
            Some(previous.servers[active_index].name().to_owned())
        };

        let mut new_server_slots = Vec::with_capacity(servers.len());
        for server in servers {
            let reusable = previous
                .servers
                .iter()
                .find(|state| state.server.as_ref() == server.as_ref())
                .cloned();
            new_server_slots.push(reusable.unwrap_or_else(|| Arc::new(ServerSlot::new(server))));
        }

        let new_active_index = previous_active_name
            .as_deref()
            .and_then(|active_name| {
                new_server_slots
                    .iter()
                    .position(|state| state.name() == active_name)
            })
            .unwrap_or(0);
        let new_set = Arc::new(ServerSet::new(new_server_slots, new_active_index));

        {
            let mut current = self
                .runtime
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *current = Arc::new(RuntimeRoutingSnapshot {
                server_set: Arc::clone(&new_set),
                proxy_downstream_obfuscation,
            });
        }
        if materially_changed {
            self.availability.reset();
        }

        if new_set.server_count() == 0 {
            log::warn!(
                "Reloaded the TACACS+ server set: no server supports authentication, authorization, and accounting; waiting for configuration"
            );
        } else {
            log::info!(
                "Reloaded the TACACS+ server set: {} server(s), active index {} ({})",
                new_set.server_count(),
                new_active_index,
                new_set.servers[new_active_index].socket_address(),
            );
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

    /// Starts a background probe for the preferred server at index `0`.
    ///
    /// The probe is idle while the preferred server is active. Thus, it creates
    /// extra connections only during failover.
    pub(crate) fn spawn_preferred_probe(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(state.preferred_probe_interval).await;
                let server_set = state.current_server_set();

                if server_set.server_count() <= 1 {
                    continue;
                }

                let active_index = *server_set.active_index.read().await;
                if active_index == 0 {
                    log::trace!(
                        "The preferred-server probe is idle because {} is active",
                        server_set.servers[0].socket_address(),
                    );
                    continue;
                }

                log::debug!(
                    "Probing preferred server {}; the active server is {}",
                    server_set.servers[0].socket_address(),
                    server_set.servers[active_index].socket_address(),
                );

                let availability_attempt = state.availability.begin_attempt();
                match state.ensure_connection(&server_set.servers[0]).await {
                    Ok(connection) => {
                        state.availability.available(availability_attempt);
                        log::info!(
                            "Preferred TACACS+ server {} recovered; routing new sessions to it",
                            connection.server_address()
                        );
                        *server_set.active_index.write().await = 0;
                    }
                    Err(error) => {
                        log::debug!(
                            "Preferred TACACS+ server {} probe failed: {error:#}",
                            server_set.servers[0].socket_address(),
                        );
                    }
                }
            }
        })
    }

    /// Selects a TACACS+ server for a new session.
    ///
    /// This method starts at `active_index` and walks the server list. It stops
    /// when it gets a connection. If a server is unavailable, the method records
    /// the failure and moves to the next server.
    ///
    /// Connection attempts are serialized for each server. Concurrent requests
    /// share one reconnect attempt. A caller waits if another task holds the
    /// server reconnect lock. It then uses the new cached connection or moves to
    /// the next server if that attempt failed.
    ///
    /// This selection path supports all operations because each server supports
    /// all required TACACS+ operations.
    ///
    /// If no eligible server is configured, this method immediately returns a
    /// retriable configuration error.
    pub(crate) async fn bind_server_for_new_session(&self) -> anyhow::Result<BoundServer> {
        let server_set = self.current_server_set();
        self.bind_server_from_set(server_set).await
    }

    pub(crate) async fn bind_proxy_server_for_new_session(
        &self,
    ) -> anyhow::Result<(BoundServer, ProxyDownstreamObfuscation)> {
        let runtime = self.current_runtime();
        let bound_server = self
            .bind_server_from_set(Arc::clone(&runtime.server_set))
            .await?;
        Ok((bound_server, runtime.proxy_downstream_obfuscation.clone()))
    }

    async fn bind_server_from_set(
        &self,
        server_set: Arc<ServerSet>,
    ) -> anyhow::Result<BoundServer> {
        if server_set.server_count() == 0 {
            bail!(
                "No configured TACACS+ server supports authentication, authorization, and accounting; waiting for initial configuration"
            );
        }
        let availability_attempt = self.availability.begin_attempt();
        let start_index = *server_set.active_index.read().await;

        for offset in 0..server_set.server_count() {
            let index = (start_index + offset) % server_set.server_count();
            match self.ensure_connection(&server_set.servers[index]).await {
                Ok(connection) => {
                    *server_set.active_index.write().await = index;
                    self.availability.available(availability_attempt);
                    return Ok(BoundServer {
                        server_set,
                        index,
                        connection,
                    });
                }
                Err(error) => {
                    log::warn!(
                        "TACACS+ server {} did not respond: {error}",
                        server_set.servers[index].socket_address()
                    );
                    self.note_failure(&server_set, index).await;
                }
            }
        }

        log::error!("No configured TACACS+ server responded; the IPC request failed");
        self.availability.unavailable(availability_attempt);
        bail!("No TACACS+ server is available");
    }

    /// Returns the cached connection for `index` or opens a new connection.
    ///
    /// Warm-up and request routing use this reconnect sequence:
    ///
    /// 1. Make sure that the cache has no connection before taking the lock.
    /// 2. Return the connection if the cache contains one.
    /// 3. Record the completed-attempt count.
    /// 4. Wait for the server connection lock.
    /// 5. Make sure that the cache still has no connection.
    /// 6. If the count changed, do not try the same server for this request.
    /// 7. Otherwise, make one connection attempt.
    /// 8. Cache a successful connection or record a failed attempt.
    ///
    /// The networking crate owns the cached connection. `tacacsrs-networking`
    /// selects dedicated or single-connection behavior when it creates a
    /// session.
    ///
    /// This method returns only server-boundary errors. Each service converts
    /// these errors for its callers.
    async fn ensure_connection(
        &self,
        server_slot: &Arc<ServerSlot>,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let existing_conn = server_slot.connection.read().await.clone();
        if let Some(existing) = existing_conn {
            log::debug!("Reusing the cached server connection to {}", server_slot.socket_address());
            return Ok(existing);
        }

        let reconnect_generation = server_slot
            .completed_connect_attempts
            .load(Ordering::Acquire);
        let _connect_guard = server_slot.connect_lock.lock().await;

        let existing_conn = server_slot.connection.read().await.clone();
        if let Some(existing) = existing_conn {
            log::debug!(
                "Reusing the cached server connection to {} after another reconnect",
                server_slot.socket_address()
            );
            return Ok(existing);
        }

        if server_slot
            .completed_connect_attempts
            .load(Ordering::Acquire)
            != reconnect_generation
        {
            log::debug!(
                "Not reconnecting to {} because another attempt completed",
                server_slot.socket_address(),
            );
            bail!(
                "Another connection attempt to TACACS+ server {} completed for this request",
                server_slot.socket_address()
            );
        }

        log::debug!("Opening a connection to TACACS+ server {}", server_slot.socket_address());
        match self
            .connector
            .connect(Arc::clone(&server_slot.server))
            .await
        {
            Ok(connection) => {
                log::info!(
                    "Opened a connection to TACACS+ server {}",
                    server_slot.socket_address(),
                );
                *server_slot.connection.write().await = Some(Arc::clone(&connection));
                server_slot
                    .completed_connect_attempts
                    .fetch_add(1, Ordering::AcqRel);
                Ok(connection)
            }
            Err(error) => {
                log::warn!(
                    "Failed to connect to upstream TACACS+ server {}: {error:#}",
                    server_slot.socket_address(),
                );
                *server_slot.connection.write().await = None;
                server_slot
                    .completed_connect_attempts
                    .fetch_add(1, Ordering::AcqRel);
                Err(error)
            }
        }
    }

    /// Records that the server at `index` failed for new sessions.
    ///
    /// This method clears the cached connection. Later callers reconnect instead
    /// of using a known bad connection. If the active server failed, the active
    /// index moves to the next server.
    ///
    /// This method does not send an IPC reply. The request path returns the
    /// error, and this method updates state for later requests.
    async fn note_failure(&self, server_set: &Arc<ServerSet>, index: usize) {
        // Order failure recording with reconnect attempts. A waiting task must
        // see the empty cache before it decides whether to reconnect.
        let _connect_guard = server_set.servers[index].connect_lock.lock().await;
        *server_set.servers[index].connection.write().await = None;
        let mut active_index = server_set.active_index.write().await;
        if *active_index == index {
            let next_index = (index + 1) % server_set.server_count();
            log::info!(
                "Failing over new TACACS+ sessions from {} to {}",
                server_set.servers[index].socket_address(),
                server_set.servers[next_index].socket_address()
            );
            *active_index = next_index;
        }
    }

    /// Records a request failure in the server set that the request used.
    pub(crate) async fn note_bound_server_failure(&self, bound_server: &BoundServer) {
        self.note_failure(&bound_server.server_set, bound_server.index)
            .await;
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
    use crate::config::ProxyDownstreamObfuscation;
    use crate::runtime::{REQUIRED_SERVER_TYPES, RuntimeHealthPublisher};
    use crate::EnabledServices;
    use crate::test_support::{FakeConnection, FakeConnector};
    use crate::upstream::UpstreamConnector;

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
            connector,
            Duration::from_secs(1),
            test_health(),
        ));

        let binding = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.bind_proxy_server_for_new_session().await })
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
        assert_eq!(state.proxy_downstream_obfuscation(), second_policy);
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
    async fn test_warm_connections_stops_after_first_responsive_server() {
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

        state.warm_connections().await;

        assert_eq!(connector.connect_attempts_for(&first.address).await, 1);
        assert_eq!(connector.connect_attempts_for(&second.address).await, 1);
        assert_eq!(connector.connect_attempts_for(&third.address).await, 0);

        let bound = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(bound.connection.server_address(), second.address);
        assert_eq!(connector.connect_attempts_for(&second.address).await, 1);
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

        state.warm_connections().await;
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

        state.warm_connections().await;
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

    #[tokio::test(start_paused = true)]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn preferred_probe_started_with_zero_servers_recovers_after_reload() {
        let preferred = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let backup = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([
            (preferred.address.clone(), Arc::clone(&preferred)),
            (backup.address.clone(), Arc::clone(&backup)),
        ])));
        let health = test_health();
        let state = Arc::new(UpstreamManager::new(
            Vec::new(),
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(25),
            health.clone(),
        ));
        let probe = state.spawn_preferred_probe();
        tokio::task::yield_now().await;

        state
            .reload_servers(vec![test_server("server-a:49"), test_server("server-b:49")])
            .await
            .expect("the reload must succeed");
        let failed_over = state
            .bind_server_for_new_session()
            .await
            .expect("the backup server must bind");
        assert_eq!(failed_over.connection.server_address(), backup.address);
        assert_eq!(
            health.snapshot().upstream_availability(),
            crate::UpstreamAvailability::Available,
        );

        tokio::time::advance(Duration::from_millis(25)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            health.snapshot().upstream_availability(),
            crate::UpstreamAvailability::Available,
        );
        preferred.usable.store(true, Ordering::Relaxed);

        tokio::time::advance(Duration::from_millis(25)).await;
        tokio::task::yield_now().await;
        let recovered = state
            .bind_server_for_new_session()
            .await
            .expect("the preferred server must recover");
        assert_eq!(recovered.connection.server_address(), preferred.address);
        assert_eq!(connector.connect_attempts_for(&preferred.address).await, 3);

        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert_eq!(connector.connect_attempts_for(&preferred.address).await, 3);
        probe.abort();
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
