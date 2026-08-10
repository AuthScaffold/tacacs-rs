//! Internal service for upstream TACACS+ server selection and failover.
//!
//! `UpstreamManager` is shared by all listener tasks. It owns the currently
//! preferred server index and cached upstream connections.
//!
//! # Concurrency model
//!
//! Multiple IPC handlers may call into `UpstreamManager` simultaneously. The
//! design uses fine-grained locking to minimize contention:
//!
//! | Lock | Scope | Purpose |
//! |------|-------|---------|
//! | `active_index` (`RwLock`) | Global | Current preferred server index |
//! | `connection` (`RwLock`) | Per-server | Cached upstream connection |
//! | `connect_lock` (`Mutex`) | Per-server | Serializes reconnect attempts |
//!
//! The per-server `connect_lock` ensures that concurrent IPC handlers share
//! one in-flight reconnect attempt instead of stampeding the same TACACS+
//! server with duplicate TLS handshakes.

use std::sync::{Arc, RwLock as StdRwLock};
use std::sync::atomic::Ordering;

use anyhow::{Context, bail};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_credential_resolution::RuntimeServer;

use self::availability::AvailabilityTracker;
use self::server_set::ServerSet;
use self::server_slot::ServerSlot;
use crate::runtime::{REQUIRED_SERVER_TYPES, RuntimeHealthPublisher};
use crate::upstream::{UpstreamConnection, UpstreamConnector};

pub(crate) use self::server_set::BoundServer;

mod server_set;
mod server_slot;
mod availability;

/// Shared runtime state for all IPC client handlers spawned by the listener.
///
/// Each incoming IPC connection calls into this type exactly once. The state
/// then binds that request to an upstream TACACS+ server, executes the
/// operation, and records any failover information needed for future requests.
///
/// The state machine maintains a circular walk through the configured server
/// list, starting from `active_index`. On failure the index advances; a
/// background probe can reset it back to `0` (the preferred server) once
/// recovery is detected.
///
/// Every server admitted into this runtime state is expected to support the
/// full TACACS+ operation set currently exposed by the agent. That lets the
/// router use one ordered failover list for accounting and authorization
/// today; if per-operation routing is introduced later, this type is the seam
/// where separate catalogs should be added.
pub(crate) struct UpstreamManager {
    /// Current immutable server-set snapshot used by new IPC requests.
    server_set: StdRwLock<Arc<ServerSet>>,
    /// Factory for creating new upstream connections.
    connector: Arc<dyn UpstreamConnector>,
    /// Interval between preferred-server recovery probes.
    preferred_probe_interval: std::time::Duration,
    /// Race-safe aggregate upstream availability publisher.
    availability: AvailabilityTracker,
}

impl UpstreamManager {
    /// Creates shared failover state for the service runtime.
    ///
    /// The runtime may start with zero configured accounting-capable upstream
    /// servers while it waits for external configuration. In that state, IPC
    /// requests fail fast with a retriable waiting-for-config error.
    pub(crate) fn new(
        servers: Vec<TacacsPlusServer>,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        let servers = servers
            .into_iter()
            .map(|server| {
                RuntimeServer::inline(server)
                    .map(Arc::new)
                    .expect("initial service configuration must contain inline credentials only")
            })
            .collect();
        Self::new_runtime(servers, connector, preferred_probe_interval, health)
    }

    pub(crate) fn new_runtime(
        servers: Vec<Arc<RuntimeServer>>,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        debug_assert!(
            servers
                .iter()
                .all(|server| server.config().supports_server_type(REQUIRED_SERVER_TYPES)),
            "UpstreamManager expects servers to support the full current TACACS+ operation set"
        );
        let servers = servers
            .into_iter()
            .map(ServerSlot::new)
            .map(Arc::new)
            .collect();
        Self {
            server_set: StdRwLock::new(Arc::new(ServerSet::new(servers, 0))),
            connector,
            preferred_probe_interval,
            availability: AvailabilityTracker::new(health),
        }
    }

    fn current_server_set(&self) -> Arc<ServerSet> {
        Arc::clone(
            &self
                .server_set
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Attempts to establish or refresh the first responsive cached connection
    /// for startup.
    ///
    /// This warm-up pass is best-effort and load-conscious: it walks the
    /// configured server list until one usable upstream connection is cached,
    /// then stops immediately. It does **not** fan out and establish
    /// connections to every configured server, because large deployments may
    /// have many more clients than TACACS+ servers.
    ///
    /// If no server is reachable during startup the service still starts; the
    /// first IPC requests will retry failover on demand.
    pub(crate) async fn warm_connections(&self) {
        let server_set = self.current_server_set();
        if server_set.server_count() == 0 {
            log::warn!(
                "No TACACS+ servers are configured yet that support authentication, authorization, and accounting; waiting for runtime configuration"
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
                    log::info!(
                        "Initialized startup upstream connection using {}",
                        connection.server_address()
                    );
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

        log::warn!(
            "Startup did not find a responsive TACACS+ server; requests will retry on demand"
        );
        self.availability.unavailable(availability_attempt);
    }

    /// Returns the number of configured upstream TACACS+ servers.
    pub(crate) fn server_count(&self) -> usize {
        self.current_server_set().server_count()
    }

    /// Atomically replaces the configured upstream TACACS+ server set.
    ///
    /// New IPC requests observe the new ordered server snapshot immediately.
    /// Requests that already bound to the previous snapshot keep running with
    /// their existing connection handles. Cached connections for unchanged
    /// servers are preserved, while removed or modified server connections are
    /// marked as not accepting new sessions and then dropped from the active
    /// runtime state.
    pub(crate) async fn reload_servers(
        &self,
        servers: Vec<TacacsPlusServer>,
    ) -> anyhow::Result<()> {
        let servers = servers
            .into_iter()
            .map(|server| {
                RuntimeServer::inline(server)
                    .map(Arc::new)
                    .context("runtime reload requires central credentials to be resolved first")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.reload_runtime_servers(servers).await
    }

    pub(crate) async fn reload_runtime_servers(
        &self,
        servers: Vec<Arc<RuntimeServer>>,
    ) -> anyhow::Result<()> {
        let previous = self.current_server_set();
        let materially_changed = previous.server_count() != servers.len()
            || previous
                .servers
                .iter()
                .zip(&servers)
                .any(|(old, new)| !runtime_servers_reusable(&old.server, new));
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
                .find(|state| runtime_servers_reusable(&state.server, &server))
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
                .server_set
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *current = Arc::clone(&new_set);
        }
        if materially_changed {
            self.availability.reset();
        }

        if new_set.server_count() == 0 {
            log::warn!(
                "Reloaded TACACS+ upstream server set: 0 servers support authentication, authorization, and accounting; waiting for runtime configuration"
            );
        } else {
            log::info!(
                "Reloaded TACACS+ upstream server set: {} server(s), active index {} ({})",
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

    /// Starts the background probe that periodically checks whether the
    /// preferred server (index `0`) has recovered while the service is failed
    /// over to another server.
    ///
    /// The probe is intentionally idle while the preferred server is already
    /// active, so it only adds extra connection work during a failover period.
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
                        "Preferred server probe: already using preferred server {}",
                        server_set.servers[0].socket_address(),
                    );
                    continue;
                }

                log::debug!(
                    "Probing preferred server {} (currently failed over to {})",
                    server_set.servers[0].socket_address(),
                    server_set.servers[active_index].socket_address(),
                );

                let availability_attempt = state.availability.begin_attempt();
                match state.ensure_connection(&server_set.servers[0]).await {
                    Ok(connection) => {
                        state.availability.available(availability_attempt);
                        log::info!(
                            "Preferred TACACS+ server {} recovered; routing new sessions back to it",
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

    /// Selects the upstream TACACS+ server for a newly accepted IPC session.
    ///
    /// This is called once per IPC client connection. It starts at the current
    /// `active_index` and walks the configured server list until it finds a
    /// reachable upstream connection manager. If a server is down, the method
    /// records that failure and advances to the next server, wrapping at the
    /// end of the list.
    ///
    /// Connection establishment is serialized per server. Concurrent IPC
    /// clients therefore share one in-flight reconnect attempt instead of
    /// stampeding the same TACACS+ server with many simultaneous handshakes.
    /// Callers that arrive while another task is reconnecting wait on that
    /// server's reconnect lock. Once the lock is released they either reuse the
    /// cached connection created by that one reconnect attempt, or skip that
    /// server for this IPC request if the reconnect attempt already failed.
    ///
    /// Because the runtime only admits servers that support every TACACS+
    /// operation the agent exposes today, this shared selection path is valid
    /// for both accounting and authorization requests.
    ///
    /// When no such servers are configured yet, the method fails immediately
    /// with a retriable waiting-for-config error instead of trying to route the
    /// request.
    pub(crate) async fn bind_server_for_new_session(&self) -> anyhow::Result<BoundServer> {
        let server_set = self.current_server_set();
        if server_set.server_count() == 0 {
            bail!(
                "No TACACS+ servers are configured yet that support authentication, authorization, and accounting; waiting for initial configuration"
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
                        "TACACS+ server {} is non-responsive: {error}",
                        server_set.servers[index].socket_address()
                    );
                    self.note_failure(&server_set, index).await;
                }
            }
        }

        log::error!(
            "All configured TACACS+ servers are currently non-responsive; failing IPC request"
        );
        self.availability.unavailable(availability_attempt);
        bail!("No responsive TACACS+ servers are currently available");
    }

    /// Returns a cached upstream connection manager for `index`, or creates a
    /// fresh one if the cache is empty.
    ///
    /// This method is the reconnect path used by both warm-up and per-request
    /// server selection. The flow is intentionally exact:
    ///
    /// 1. check the cached connection without taking the per-server connect lock
    /// 2. if it exists, return it immediately
    /// 3. record the current completed-reconnect generation for this server
    /// 4. wait for the per-server connect lock so only one task can reconnect
    /// 5. once the lock is held, re-check the cache because another waiter may
    ///    already have populated it
    /// 6. if the reconnect generation changed while this caller waited, then
    ///    another task already completed the one allowed reconnect attempt; do
    ///    not immediately retry the same server again for this request
    /// 7. otherwise perform one real upstream connect attempt
    /// 8. cache the successful connection so queued callers reuse it, or mark
    ///    that one reconnect attempt as completed so queued callers fail over
    ///
    /// The cached value is a networking-owned connection manager rather than a
    /// raw transport. Dedicated versus single-connection behavior is handled
    /// inside `tacacsrs-networking` when an operation creates a session.
    ///
    /// This method returns upstream boundary errors only; each consuming
    /// service decides how to translate those errors for its own callers.
    async fn ensure_connection(
        &self,
        server_slot: &Arc<ServerSlot>,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let existing_conn = server_slot.connection.read().await.clone();
        if let Some(existing) = existing_conn {
            log::debug!(
                "Reusing cached upstream connection manager for {}",
                server_slot.socket_address()
            );
            return Ok(existing);
        }

        let reconnect_generation = server_slot
            .completed_connect_attempts
            .load(Ordering::Acquire);
        let _connect_guard = server_slot.connect_lock.lock().await;

        let existing_conn = server_slot.connection.read().await.clone();
        if let Some(existing) = existing_conn {
            log::debug!(
                "Reusing cached upstream connection manager for {} after waiting on another reconnect",
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
                "Skipping duplicate reconnect to {}; another attempt already completed",
                server_slot.socket_address(),
            );
            bail!(
                "Another reconnect attempt for TACACS+ server {} already completed for this request wave",
                server_slot.socket_address()
            );
        }

        log::debug!("Opening upstream connection to {}", server_slot.socket_address());
        match self
            .connector
            .connect(Arc::clone(&server_slot.server))
            .await
        {
            Ok(connection) => {
                log::info!(
                    "Upstream connection to {} established successfully",
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

    /// Records that the server at `index` failed for new-session purposes.
    ///
    /// This clears the cached connection so future callers reconnect instead of
    /// reusing a known-bad handle. If the failed server was the current
    /// preferred choice for new sessions, the active index is advanced so later
    /// IPC clients start from the next server in the ordered list.
    ///
    /// This does not itself send any reply to IPC clients. The client that hit
    /// the failure receives the error from the request execution path, while
    /// this method updates shared state for subsequent clients.
    async fn note_failure(&self, server_set: &Arc<ServerSet>, index: usize) {
        // Keep request-time failure recording ordered with reconnect attempts
        // so a waiter that is about to reconnect observes the cleared cache
        // before it decides whether it must establish a fresh connection.
        let _connect_guard = server_set.servers[index].connect_lock.lock().await;
        *server_set.servers[index].connection.write().await = None;
        let mut active_index = server_set.active_index.write().await;
        if *active_index == index {
            let next_index = (index + 1) % server_set.server_count();
            log::info!(
                "Failing over new IPC sessions from {} to {}",
                server_set.servers[index].socket_address(),
                server_set.servers[next_index].socket_address()
            );
            *active_index = next_index;
        }
    }

    /// Records a request failure against the server snapshot that request used.
    pub(crate) async fn note_bound_server_failure(&self, bound_server: &BoundServer) {
        self.note_failure(&bound_server.server_set, bound_server.index)
            .await;
    }
}

fn runtime_servers_reusable(left: &RuntimeServer, right: &RuntimeServer) -> bool {
    if left.has_resolved_credentials() || right.has_resolved_credentials() {
        return false;
    }
    left.config() == right.config()
}

#[cfg(test)]
mod tests {
    use tacacsrs_credential_resolution::{
        FakeCredentialResolver, ResolutionPlan, ResolvedCredential, RuntimeServer, SecretBytes,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tacacsrs_config::TacacsPlusServer;
    use super::{BoundServer, UpstreamManager, runtime_servers_reusable};
    use crate::runtime::{REQUIRED_SERVER_TYPES, RuntimeHealthPublisher};
    use crate::EnabledServices;
    use crate::test_support::{FakeConnection, FakeConnector};
    use crate::upstream::UpstreamConnector;

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

    async fn resolved_runtime(reference: &str, secret: &[u8]) -> RuntimeServer {
        let json = format!(
            r#"{{
                "ietf-system-tacacs-plus:tacacs-plus": {{
                    "server": [{{
                        "name": "rotation-test",
                        "server-type": "authentication authorization accounting",
                        "address": "192.0.2.70",
                        "port": 449,
                        "client-identity": {{
                            "tls13-epsk": {{
                                "central-keystore-reference": "{reference}",
                                "external-identity": "client"
                            }}
                        }}
                    }}]
                }}
            }}"#,
        );
        let server = tacacsrs_config::parse_yang_json(&json)
            .expect("central config")
            .server
            .remove(0);
        let plan = ResolutionPlan::from_server(&server).expect("plan");
        let resolver = FakeCredentialResolver::new().with_response(
            plan.requests()[0].slot(),
            ResolvedCredential::SymmetricKey(SecretBytes::new(secret.to_vec())),
        );
        RuntimeServer::resolve(server, &resolver)
            .await
            .expect("resolved runtime")
    }

    fn bound_secret(bound: &BoundServer) -> &[u8] {
        bound
            .runtime_server()
            .tls13_epsk_secret()
            .expect("resolved secret")
            .expose_secret()
    }

    #[tokio::test]
    async fn centrally_resolved_servers_are_never_reused_by_reference_equivalence() {
        let first = resolved_runtime("same-object-id", b"first-secret-material").await;
        let replacement = resolved_runtime("same-object-id", b"replacement-secret").await;

        assert!(!runtime_servers_reusable(&first, &replacement));
        assert_ne!(
            first
                .tls13_epsk_secret()
                .expect("first secret")
                .expose_secret(),
            replacement
                .tls13_epsk_secret()
                .expect("replacement secret")
                .expose_secret()
        );
    }

    #[test]
    fn inline_shared_secret_change_prevents_runtime_server_reuse() {
        let mut first = test_server("192.0.2.70:49");
        first.shared_secret = Some(tacacsrs_secrets::SecretString::new("first-secret".to_owned()));
        let same = RuntimeServer::inline(first.clone()).expect("inline server");
        let first = RuntimeServer::inline(first).expect("inline server");

        let mut replacement = test_server("192.0.2.70:49");
        replacement.shared_secret =
            Some(tacacsrs_secrets::SecretString::new("replacement-secret".to_owned()));
        let replacement = RuntimeServer::inline(replacement).expect("inline server");

        assert!(runtime_servers_reusable(&first, &same));
        assert!(!runtime_servers_reusable(&first, &replacement));
    }

    #[tokio::test]
    async fn resolved_rotation_replaces_new_bindings_and_preserves_existing_snapshots() {
        let first = Arc::new(resolved_runtime("object-a", b"first-secret-material").await);
        let second = Arc::new(resolved_runtime("object-b", b"second-secret-material").await);
        let rollback = Arc::new(resolved_runtime("object-a", b"first-secret-material").await);
        let connection = Arc::new(FakeConnection {
            address: "192.0.2.70:449".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            connection.address.clone(),
            Arc::clone(&connection),
        )])));
        let state = UpstreamManager::new_runtime(
            vec![Arc::clone(&first)],
            connector,
            Duration::from_secs(1),
            test_health(),
        );

        let first_binding = state.bind_server_for_new_session().await.expect("bind A");
        state
            .reload_runtime_servers(vec![second])
            .await
            .expect("apply B");
        connection.usable.store(true, Ordering::Relaxed);
        let second_binding = state.bind_server_for_new_session().await.expect("bind B");
        state
            .reload_runtime_servers(vec![rollback])
            .await
            .expect("roll back to A");
        connection.usable.store(true, Ordering::Relaxed);
        let rollback_binding = state
            .bind_server_for_new_session()
            .await
            .expect("bind rollback A");

        assert_eq!(bound_secret(&first_binding), b"first-secret-material");
        assert_eq!(bound_secret(&second_binding), b"second-secret-material");
        assert_eq!(bound_secret(&rollback_binding), b"first-secret-material");
        assert_eq!(bound_secret(&first_binding), b"first-secret-material");
    }

    fn test_health() -> RuntimeHealthPublisher {
        RuntimeHealthPublisher::new(EnabledServices::CLIENT_API)
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
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
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
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
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
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
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
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
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
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
            .expect("reload should succeed");
        let failed_over = state
            .bind_server_for_new_session()
            .await
            .expect("backup should bind");
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
            .expect("preferred should recover");
        assert_eq!(recovered.connection.server_address(), preferred.address);
        assert_eq!(connector.connect_attempts_for(&preferred.address).await, 3);

        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert_eq!(connector.connect_attempts_for(&preferred.address).await, 3);
        probe.abort();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio sync not supported
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
    #[cfg_attr(miri, ignore)] // tokio sync not supported
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
            .expect("server should bind");
        assert_eq!(
            health.snapshot().upstream_availability(),
            crate::UpstreamAvailability::Available,
        );

        state
            .reload_servers(vec![test_server("server-a:49"), test_server("server-b:49")])
            .await
            .expect("reload should succeed");

        assert_eq!(health.snapshot().upstream_availability(), crate::UpstreamAvailability::Unknown,);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
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
