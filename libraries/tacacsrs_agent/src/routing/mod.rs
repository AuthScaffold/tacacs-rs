//! Internal state machine for IPC request routing and TACACS+ server failover.
//!
//! `RoutingState` is shared by all listener tasks. It owns the currently
//! preferred server index, cached upstream connections, and the active-client
//! drain tracking used during graceful shutdown.
//!
//! # Concurrency model
//!
//! Multiple IPC handlers may call into `RoutingState` simultaneously. The
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

use anyhow::bail;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};

use self::client_tracker::{ClientGuard, ClientTracker};
use self::server_set::{BoundServer, ServerSet, servers_equivalent};
use self::server_slot::ServerSlot;
use crate::runtime::REQUIRED_SERVER_TYPES;
use crate::upstream::{UpstreamConnection, UpstreamConnector};

mod client_tracker;
mod server_set;
mod server_slot;

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
pub(crate) struct RoutingState {
    /// Current immutable server-set snapshot used by new IPC requests.
    server_set: StdRwLock<Arc<ServerSet>>,
    /// Factory for creating new upstream connections.
    connector: Arc<dyn UpstreamConnector>,
    /// Interval between preferred-server recovery probes.
    preferred_probe_interval: std::time::Duration,
    /// Tracks in-flight IPC handlers for graceful shutdown draining.
    client_tracker: Arc<ClientTracker>,
}

impl RoutingState {
    /// Creates shared failover state for the service runtime.
    ///
    /// The runtime may start with zero configured accounting-capable upstream
    /// servers while it waits for external configuration. In that state, IPC
    /// requests fail fast with a retriable waiting-for-config error.
    pub(crate) fn new(
        servers: Vec<TacacsPlusServer>,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
    ) -> Self {
        debug_assert!(
            servers
                .iter()
                .all(|server| server.supports_server_type(REQUIRED_SERVER_TYPES)),
            "RoutingState expects servers to support the full current TACACS+ operation set"
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
            client_tracker: Arc::new(ClientTracker::default()),
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
        let start_index = *server_set.active_index.read().await;

        for offset in 0..server_set.server_count() {
            let index = (start_index + offset) % server_set.server_count();
            match self.ensure_connection(&server_set.servers[index]).await {
                Ok(connection) => {
                    *server_set.active_index.write().await = index;
                    log::info!(
                        "Initialized startup upstream connection using {}",
                        connection.server_address()
                    );
                    return;
                }
                Err(error) => {
                    log::warn!(
                        "Initial connection attempt to {} failed: {error}",
                        server_set.servers[index].server.socket_address()
                    );
                }
            }
        }

        log::warn!(
            "Startup did not find a responsive TACACS+ server; requests will retry on demand"
        );
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
        let previous = self.current_server_set();
        let previous_active_name = if previous.server_count() == 0 {
            None
        } else {
            let active_index = *previous.active_index.read().await;
            Some(previous.servers[active_index].server.name.clone())
        };

        let mut new_server_slots = Vec::with_capacity(servers.len());
        for server in servers {
            let reusable = previous
                .servers
                .iter()
                .find(|state| {
                    state.server.name == server.name && servers_equivalent(&state.server, &server)
                })
                .cloned();
            new_server_slots.push(reusable.unwrap_or_else(|| Arc::new(ServerSlot::new(server))));
        }

        let new_active_index = previous_active_name
            .as_deref()
            .and_then(|active_name| {
                new_server_slots
                    .iter()
                    .position(|state| state.server.name == active_name)
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

        if new_set.server_count() == 0 {
            log::warn!(
                "Reloaded TACACS+ upstream server set: 0 servers support authentication, authorization, and accounting; waiting for runtime configuration"
            );
        } else {
            log::info!(
                "Reloaded TACACS+ upstream server set: {} server(s), active index {} ({})",
                new_set.server_count(),
                new_active_index,
                new_set.servers[new_active_index].server.socket_address(),
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
                        server_set.servers[0].server.socket_address(),
                    );
                    continue;
                }

                log::debug!(
                    "Probing preferred server {} (currently failed over to {})",
                    server_set.servers[0].server.socket_address(),
                    server_set.servers[active_index].server.socket_address(),
                );

                match state.ensure_connection(&server_set.servers[0]).await {
                    Ok(connection) => {
                        log::info!(
                            "Preferred TACACS+ server {} recovered; routing new sessions back to it",
                            connection.server_address()
                        );
                        *server_set.active_index.write().await = 0;
                    }
                    Err(error) => {
                        log::debug!(
                            "Preferred TACACS+ server {} probe failed: {error:#}",
                            server_set.servers[0].server.socket_address(),
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
        let start_index = *server_set.active_index.read().await;

        for offset in 0..server_set.server_count() {
            let index = (start_index + offset) % server_set.server_count();
            match self.ensure_connection(&server_set.servers[index]).await {
                Ok(connection) => {
                    *server_set.active_index.write().await = index;
                    return Ok(BoundServer {
                        server_set,
                        index,
                        connection,
                    });
                }
                Err(error) => {
                    log::warn!(
                        "TACACS+ server {} is non-responsive: {error}",
                        server_set.servers[index].server.socket_address()
                    );
                    self.note_failure(&server_set, index).await;
                }
            }
        }

        log::error!(
            "All configured TACACS+ servers are currently non-responsive; failing IPC request"
        );
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
    /// This method does not notify IPC clients directly; callers translate any
    /// returned error into a retriable
    /// [`tacacsrs_agent_client::ServiceError`] for
    /// the affected IPC request.
    async fn ensure_connection(
        &self,
        server_slot: &Arc<ServerSlot>,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let existing_conn = server_slot.connection.read().await.clone();
        if let Some(existing) = existing_conn {
            log::debug!(
                "Reusing cached upstream connection manager for {}",
                server_slot.server.socket_address()
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
                server_slot.server.socket_address()
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
                server_slot.server.socket_address(),
            );
            bail!(
                "Another reconnect attempt for TACACS+ server {} already completed for this request wave",
                server_slot.server.socket_address()
            );
        }

        log::debug!("Opening upstream connection to {}", server_slot.server.socket_address());
        match self.connector.connect(&server_slot.server).await {
            Ok(connection) => {
                log::info!(
                    "Upstream connection to {} established successfully",
                    server_slot.server.socket_address(),
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
                    server_slot.server.socket_address(),
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
                server_set.servers[index].server.socket_address(),
                server_set.servers[next_index].server.socket_address()
            );
            *active_index = next_index;
        }
    }

    /// Registers one active IPC request and returns a guard held by the caller
    /// until the request has finished.
    pub(crate) fn start_client_request(&self) -> ClientGuard {
        self.client_tracker.start_guard()
    }

    /// Records a request failure against the server snapshot that request used.
    pub(crate) async fn note_bound_server_failure(&self, bound_server: &BoundServer) {
        self.note_failure(&bound_server.server_set, bound_server.index)
            .await;
    }

    /// Waits for all IPC client handlers to complete after the listener has
    /// stopped accepting new connections.
    pub(crate) async fn wait_for_active_clients(&self) {
        self.client_tracker.wait_for_zero().await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tacacsrs_config::TacacsPlusServer;
    use tokio::sync::Notify;

    use super::RoutingState;
    use crate::runtime::REQUIRED_SERVER_TYPES;
    use crate::test_support::{
        BlockingConnection, BlockingConnector, FakeConnection, FakeConnector,
        build_authorization_request, build_request,
    };
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

        let state = RoutingState::new(
            vec![
                test_server("server-a:49"),
                test_server("server-b:49"),
                test_server("server-c:49"),
            ],
            connector,
            Duration::from_millis(25),
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

        let state = RoutingState::new(
            vec![
                test_server("server-a:49"),
                test_server("server-b:49"),
                test_server("server-c:49"),
            ],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(25),
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

        let state = RoutingState::new(
            vec![test_server("server-a:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(25),
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

        let state = RoutingState::new(
            vec![test_server("server-a:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(25),
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

        let state = Arc::new(RoutingState::new(
            vec![test_server("server-a:49"), test_server("server-b:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
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

    // -----------------------------------------------------------------------
    // ClientTracker / drain-wait tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
    async fn test_drain_returns_immediately_with_no_active_clients() {
        let release = Arc::new(Notify::new());
        let connector = Arc::new(BlockingConnector {
            connection: Arc::new(BlockingConnection {
                address: "server:49".to_owned(),
                release,
            }),
        });
        #[allow(unknown_lints, clippy::duration_suboptimal_units)]
        let state =
            RoutingState::new(vec![test_server("server:49")], connector, Duration::from_secs(60));

        // No requests in flight — drain should return immediately.
        tokio::time::timeout(Duration::from_millis(100), state.wait_for_active_clients())
            .await
            .expect("wait_for_active_clients should return immediately with no active clients");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
    async fn test_drain_waits_for_in_flight_request_then_completes() {
        let release = Arc::new(Notify::new());
        let connector = Arc::new(BlockingConnector {
            connection: Arc::new(BlockingConnection {
                address: "server:49".to_owned(),
                release: Arc::clone(&release),
            }),
        });
        #[allow(unknown_lints, clippy::duration_suboptimal_units)]
        let state = Arc::new(RoutingState::new(
            vec![test_server("server:49")],
            connector,
            Duration::from_secs(60),
        ));
        state.warm_connections().await;

        // Spawn an in-flight request that blocks inside send_accounting.
        let state_bg = Arc::clone(&state);
        let request_handle = tokio::spawn(async move {
            state_bg
                .execute_accounting_request(build_request())
                .await
                .unwrap();
        });

        // Give the spawned task time to enter send_accounting and acquire the guard.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Drain should NOT complete while the request is in flight.
        let drain_result =
            tokio::time::timeout(Duration::from_millis(100), state.wait_for_active_clients()).await;
        assert!(
            drain_result.is_err(),
            "wait_for_active_clients should block while a request is in flight"
        );

        // Release the blocked request so the guard drops.
        release.notify_waiters();
        request_handle.await.unwrap();

        // Now drain should complete promptly.
        tokio::time::timeout(Duration::from_millis(100), state.wait_for_active_clients())
            .await
            .expect("wait_for_active_clients should complete after all requests finish");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
    async fn test_drain_completes_when_guard_drops_between_check_and_await() {
        // Regression test for the lost-wakeup race: the guard drops (and
        // notifies) in the window between the load-check and the notified().await
        // inside wait_for_zero. The fix ensures the Notify future is registered
        // before the recheck so no wakeup is lost.
        let release = Arc::new(Notify::new());
        let connector = Arc::new(BlockingConnector {
            connection: Arc::new(BlockingConnection {
                address: "server:49".to_owned(),
                release: Arc::clone(&release),
            }),
        });
        #[allow(unknown_lints, clippy::duration_suboptimal_units)]
        let state = Arc::new(RoutingState::new(
            vec![test_server("server:49")],
            connector,
            Duration::from_secs(60),
        ));
        state.warm_connections().await;

        // Spawn a request then release it almost immediately so the guard drop
        // races with the drain waiter.
        let state_bg = Arc::clone(&state);
        let request_handle = tokio::spawn(async move {
            state_bg
                .execute_accounting_request(build_request())
                .await
                .unwrap();
        });

        // Yield briefly to let the task start.
        tokio::task::yield_now().await;

        // Release the request immediately — the guard will drop while the drain
        // waiter is still setting up, exercising the race window.
        release.notify_waiters();
        request_handle.await.unwrap();

        // Drain must still complete; a lost wakeup would cause this to hang.
        tokio::time::timeout(Duration::from_millis(200), state.wait_for_active_clients())
            .await
            .expect("wait_for_active_clients must not hang after a racing guard drop");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
    async fn test_authorization_request_uses_configured_upstream_server() {
        let connection = Arc::new(FakeConnection {
            address: "server:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            "server:49".to_owned(),
            Arc::clone(&connection),
        )])));

        let state = RoutingState::new(
            vec![test_server("server:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
        );

        let response = state
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap();

        assert_eq!(response.server, "server:49");
        assert_eq!(connector.connect_attempts_for("server:49").await, 1);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
    async fn test_authorization_failure_returns_service_error_and_fails_over() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(true),
        });
        let secondary = Arc::new(FakeConnection {
            address: "secondary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([
            ("primary:49".to_owned(), Arc::clone(&primary)),
            ("secondary:49".to_owned(), Arc::clone(&secondary)),
        ])));

        let state = RoutingState::new(
            vec![test_server("primary:49"), test_server("secondary:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
        );

        let error = state
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap_err();
        assert_eq!(error.server.as_deref(), Some("primary:49"));
        assert!(error.retriable);

        let response = state
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap();
        assert_eq!(response.server, "secondary:49");
    }

    #[tokio::test]
    async fn test_request_without_configured_servers_returns_waiting_error() {
        let state = RoutingState::new(
            Vec::new(),
            Arc::new(FakeConnector::new(HashMap::new())) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
        );

        let error = state
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap_err();

        assert!(error.retriable);
        assert!(error.message.contains("waiting for initial configuration"));
    }
}
