//! Internal state machine for IPC request routing and TACACS+ server failover.
//!
//! [`ServiceState`] is shared by all listener tasks. It owns the currently
//! preferred server index, cached upstream connections, and the active-client
//! drain tracking used during graceful shutdown.
//!
//! # Concurrency model
//!
//! Multiple IPC handlers may call into `ServiceState` simultaneously. The
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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use anyhow::bail;
use tacacsrs_agent_client::{AccountingOperation, AccountingOperationResponse, ServiceError};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_networking::SingleConnectionState;
use tokio::sync::{Mutex, Notify, RwLock};

use crate::upstream::{UpstreamConnection, UpstreamConnector};

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
pub(super) struct ServiceState {
    /// Per-server state including cached connections and reconnect locks.
    servers: Vec<ServerState>,
    /// Factory for creating new upstream connections.
    connector: Arc<dyn UpstreamConnector>,
    /// Index into `servers` of the currently preferred server for new sessions.
    active_index: RwLock<usize>,
    /// Interval between preferred-server recovery probes.
    preferred_probe_interval: std::time::Duration,
    /// Tracks in-flight IPC handlers for graceful shutdown draining.
    client_tracker: Arc<ClientTracker>,
}

/// Per-server cached connection state.
///
/// Each configured TACACS+ server gets its own `ServerState` so that
/// reconnect serialization and connection caching are independent.
struct ServerState {
    /// The per-server connection configuration.
    server: TacacsPlusServer,
    /// Cached upstream connection, if any. `None` means the server needs
    /// a fresh connection on the next request.
    connection: RwLock<Option<Arc<dyn UpstreamConnection>>>,
    /// Lock that serializes reconnect attempts for this server.
    connect_lock: Mutex<()>,
    /// Monotonically increasing counter of completed connect attempts.
    /// Used to detect when another task has already reconnected while
    /// this task was waiting for the lock.
    completed_connect_attempts: AtomicU64,
    /// Whether this server has been observed to support TACACS+
    /// single-connection mode.
    ///
    /// Starts `false` (pessimistic — assume dedicated connections until
    /// proven otherwise).  Set to `true` when a completed session reports
    /// [`SingleConnectionState::Supported`], allowing future requests to
    /// multiplex over the shared cached connection.  Can revert to `false`
    /// if the server later withdraws support (e.g. traffic-shifting).
    single_connection_supported: AtomicBool,
}

/// The result of binding an IPC request to an upstream server.
///
/// Contains both the server index (for recording failover) and the
/// connection handle (for executing the request).
pub(super) struct BoundServer {
    /// Index into the service's server list.
    pub(super) index: usize,
    /// The upstream connection to use for this request.
    pub(super) connection: Arc<dyn UpstreamConnection>,
}

/// Tracks how many client handlers are currently executing so shutdown can stop
/// accepting new work first and then wait for in-flight requests to complete.
///
/// The tracker uses an atomic counter plus a [`Notify`] to avoid holding a
/// lock during the entire RPC handler lifetime. Incrementing and decrementing
/// the counter is lock-free; only the shutdown waiter blocks on the notification.
#[derive(Default)]
struct ClientTracker {
    /// Number of IPC handlers currently executing a request.
    active_clients: AtomicUsize,
    /// Notification signalled when `active_clients` reaches zero.
    drained: Notify,
}

/// RAII guard that decrements the active-client count on drop.
///
/// Created by [`ClientTracker::start_guard`] and held for the duration of
/// one IPC request handler. When the last guard drops, the tracker notifies
/// the shutdown waiter.
struct ClientGuard {
    tracker: Arc<ClientTracker>,
}

impl ClientTracker {
    /// Registers one active client handler and returns a guard that will
    /// decrement the count automatically when the handler finishes.
    fn start_guard(self: &Arc<Self>) -> ClientGuard {
        self.active_clients.fetch_add(1, Ordering::Relaxed);
        ClientGuard {
            tracker: Arc::clone(self),
        }
    }

    /// Waits until all client handlers tracked by this instance have dropped
    /// their guards.
    ///
    /// This is used only during shutdown after the listeners have stopped
    /// accepting new connections, so the count is expected to trend toward
    /// zero. The loop handles races where a notification arrives just before a
    /// waiter starts sleeping.
    async fn wait_for_zero(&self) {
        loop {
            if self.active_clients.load(Ordering::Relaxed) == 0 {
                log::debug!("All in-flight IPC client handlers have drained");
                return;
            }

            // Register for notification *before* the recheck so that a
            // decrement-to-zero that races between the recheck and the await
            // is captured by the already-registered future.
            let notified = self.drained.notified();

            let active_clients = self.active_clients.load(Ordering::Relaxed);
            if active_clients == 0 {
                log::debug!("All in-flight IPC client handlers have drained");
                return;
            }

            log::debug!("Waiting for {active_clients} in-flight IPC client handler(s) to finish");
            notified.await;
        }
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        if self.tracker.active_clients.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.tracker.drained.notify_waiters();
        }
    }
}

impl ServiceState {
    /// Creates shared failover state for the service runtime.
    ///
    /// The caller is expected to validate that at least one upstream server is
    /// configured before constructing this state. The higher-level service
    /// constructor enforces that invariant for production use.
    pub(super) fn new(
        servers: Vec<TacacsPlusServer>,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
    ) -> Self {
        Self {
            servers: servers
                .into_iter()
                .map(|server| ServerState {
                    server,
                    connection: RwLock::new(None),
                    connect_lock: Mutex::new(()),
                    completed_connect_attempts: AtomicU64::new(0),
                    single_connection_supported: AtomicBool::new(false),
                })
                .collect(),
            connector,
            active_index: RwLock::new(0),
            preferred_probe_interval,
            client_tracker: Arc::new(ClientTracker::default()),
        }
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
    pub(super) async fn warm_connections(&self) {
        let start_index = *self.active_index.read().await;

        for offset in 0..self.servers.len() {
            let index = (start_index + offset) % self.servers.len();
            match self.ensure_connection(index).await {
                Ok(connection) => {
                    *self.active_index.write().await = index;
                    log::info!(
                        "Initialized startup upstream connection using {}",
                        connection.server_address()
                    );
                    return;
                }
                Err(error) => {
                    log::warn!(
                        "Initial connection attempt to {} failed: {error}",
                        self.servers[index].server.socket_address()
                    );
                }
            }
        }

        log::warn!(
            "Startup did not find a responsive TACACS+ server; requests will retry on demand"
        );
    }

    /// Returns the number of configured upstream TACACS+ servers.
    pub(super) fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Starts the background probe that periodically checks whether the
    /// preferred server (index `0`) has recovered while the service is failed
    /// over to another server.
    ///
    /// The probe is intentionally idle while the preferred server is already
    /// active, so it only adds extra connection work during a failover period.
    pub(super) fn spawn_preferred_probe(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(state.preferred_probe_interval).await;

                if state.servers.len() <= 1 {
                    continue;
                }

                let active_index = *state.active_index.read().await;
                if active_index == 0 {
                    log::trace!(
                        "Preferred server probe: already using preferred server {}",
                        state.servers[0].server.socket_address(),
                    );
                    continue;
                }

                log::debug!(
                    "Probing preferred server {} (currently failed over to {})",
                    state.servers[0].server.socket_address(),
                    state.servers[active_index].server.socket_address(),
                );

                match state.ensure_connection(0).await {
                    Ok(connection) => {
                        log::info!(
                            "Preferred TACACS+ server {} recovered; routing new sessions back to it",
                            connection.server_address()
                        );
                        *state.active_index.write().await = 0;
                    }
                    Err(error) => {
                        log::debug!(
                            "Preferred TACACS+ server {} probe failed: {error:#}",
                            state.servers[0].server.socket_address(),
                        );
                    }
                }
            }
        })
    }

    /// Executes one IPC accounting RPC against the currently selected upstream
    /// TACACS+ server.
    ///
    /// # Connection strategy
    ///
    /// By default every request gets its own dedicated short-lived TCP
    /// connection (the safe path for servers that do not support
    /// single-connection mode).
    ///
    /// Once a server proves it supports single-connection mode
    /// ([`SingleConnectionState::Supported`]), future requests multiplex
    /// sessions over a shared cached connection.  The server may later
    /// withdraw that support (e.g. for traffic-shifting), in which case the
    /// service reverts to dedicated connections.
    pub(super) async fn execute_accounting_request(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        let _client_guard = self.client_tracker.start_guard();
        let active_index = *self.active_index.read().await;

        // When the server has proven single-connection support, reuse the
        // shared cached connection for session multiplexing.
        if self.servers[active_index]
            .single_connection_supported
            .load(Ordering::Relaxed)
        {
            return self.execute_on_shared_connection(&request).await;
        }

        // Default path: one dedicated TCP connection per request.
        self.execute_with_dedicated_connection(active_index, &request)
            .await
    }

    /// Executes a request over the shared cached connection (single-connection
    /// mode).
    ///
    /// If the cached connection becomes unusable mid-request (e.g. the server
    /// revoked single-connection support), the request is transparently
    /// retried on a fresh dedicated connection.
    async fn execute_on_shared_connection(
        &self,
        request: &AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        let bound_server = self.bind_server_for_new_session().await.map_err(|error| {
            log::warn!("Failed to bind IPC request to an upstream server: {error:#}");
            ServiceError::new(error.to_string()).retriable(true)
        })?;

        log::debug!(
            "Executing accounting request via {} (server index {}, shared connection)",
            bound_server.connection.server_address(),
            bound_server.index,
        );

        match bound_server.connection.send_accounting(request).await {
            Ok(response) => {
                self.check_single_connection_negotiation(
                    bound_server.index,
                    &*bound_server.connection,
                )
                .await;
                Ok(response)
            }
            Err(error) => {
                // If the connection is no longer usable for new sessions the
                // failure is a local connection-capacity issue (the server may
                // have revoked single-connection support), not a remote server
                // outage.  Fall back to a dedicated connection.
                if !bound_server.connection.is_usable_for_new_sessions().await {
                    log::info!(
                        "Shared connection to {} no longer usable; \
                         falling back to a dedicated connection",
                        self.servers[bound_server.index].server.socket_address(),
                    );
                    self.check_single_connection_negotiation(
                        bound_server.index,
                        &*bound_server.connection,
                    )
                    .await;
                    return self
                        .execute_with_dedicated_connection(bound_server.index, request)
                        .await;
                }

                log::warn!(
                    "Accounting request failed on {}: {error:#}",
                    bound_server.connection.server_address(),
                );
                self.note_failure(bound_server.index).await;
                Err(ServiceError::new(error.to_string())
                    .with_server(bound_server.connection.server_address())
                    .retriable(true))
            }
        }
    }

    /// Sends a single accounting request over a dedicated one-shot TCP
    /// connection (no background tasks, no session multiplexing).
    ///
    /// This is the default path.  Each IPC request gets its own short-lived
    /// upstream TCP connection, which is discarded after the response.
    /// The outgoing packet includes the single-connect flag so the server's
    /// response reveals whether it supports multiplexing; if it does, the
    /// per-server flag is set so future requests upgrade to the shared
    /// cached-connection path.
    async fn execute_with_dedicated_connection(
        &self,
        index: usize,
        request: &AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        let address = self.servers[index].server.socket_address();
        log::debug!("Sending dedicated accounting request to {address}");

        match self
            .connector
            .send_accounting_dedicated(&self.servers[index].server, request)
            .await
        {
            Ok(result) => {
                if result.single_connect_supported
                    && !self.servers[index]
                        .single_connection_supported
                        .swap(true, Ordering::Relaxed)
                {
                    log::info!(
                        "Server {address} supports single-connection mode; \
                         switching to shared connections for future requests",
                    );
                }
                Ok(result.response)
            }
            Err(error) => {
                log::warn!("Dedicated accounting request to {address} failed: {error:#}");
                self.note_failure(index).await;
                Err(ServiceError::new(error.to_string())
                    .with_server(&address)
                    .retriable(true))
            }
        }
    }

    /// Inspects the single-connection negotiation result on `connection` and
    /// updates the per-server flag in either direction.
    ///
    /// - [`Supported`](SingleConnectionState::Supported) → enables the shared
    ///   cached-connection path for future requests.
    /// - [`NotSupported`](SingleConnectionState::NotSupported) → reverts to
    ///   dedicated per-request connections (e.g. the server withdrew support
    ///   for traffic-shifting).
    /// - `Initial` / `Negotiating` — no actionable information yet.
    async fn check_single_connection_negotiation(
        &self,
        index: usize,
        connection: &dyn UpstreamConnection,
    ) {
        match connection.single_connection_state().await {
            SingleConnectionState::Supported
                if !self.servers[index]
                    .single_connection_supported
                    .swap(true, Ordering::Relaxed) =>
            {
                log::info!(
                    "Server {} supports single-connection mode; \
                         switching to shared connections for future requests",
                    self.servers[index].server.socket_address(),
                );
            }
            SingleConnectionState::NotSupported
                if self.servers[index]
                    .single_connection_supported
                    .swap(false, Ordering::Relaxed) =>
            {
                log::info!(
                    "Server {} revoked single-connection support; \
                         switching to dedicated connections for future requests",
                    self.servers[index].server.socket_address(),
                );
            }
            // Initial or Negotiating — no actionable information yet.
            _ => {}
        }
    }

    /// Selects the upstream TACACS+ server for a newly accepted IPC session.
    ///
    /// This is called once per IPC client connection. It starts at the current
    /// `active_index` and walks the configured server list until it finds a
    /// connection that can accept a new session. If a server is down or returns
    /// an unusable connection, the method records that failure and advances to
    /// the next server, wrapping at the end of the list.
    ///
    /// Connection establishment is serialized per server. Concurrent IPC
    /// clients therefore share one in-flight reconnect attempt instead of
    /// stampeding the same TACACS+ server with many simultaneous handshakes.
    /// Callers that arrive while another task is reconnecting wait on that
    /// server's reconnect lock. Once the lock is released they either reuse the
    /// cached connection created by that one reconnect attempt, or skip that
    /// server for this IPC request if the reconnect attempt already failed.
    ///
    /// The service constructor rejects an empty server list up front, so the
    /// final "no responsive servers" error indicates that all configured
    /// servers are currently unavailable rather than that startup accepted an
    /// invalid configuration.
    pub(super) async fn bind_server_for_new_session(&self) -> anyhow::Result<BoundServer> {
        let start_index = *self.active_index.read().await;

        for offset in 0..self.servers.len() {
            let index = (start_index + offset) % self.servers.len();
            match self.ensure_connection(index).await {
                Ok(connection) => {
                    *self.active_index.write().await = index;
                    return Ok(BoundServer { index, connection });
                }
                Err(error) => {
                    log::warn!(
                        "TACACS+ server {} is non-responsive: {error}",
                        self.servers[index].server.socket_address()
                    );
                    self.note_failure(index).await;
                }
            }
        }

        log::error!(
            "All configured TACACS+ servers are currently non-responsive; failing IPC request"
        );
        bail!("No responsive TACACS+ servers are currently available");
    }

    /// Returns a usable cached connection for `index`, or creates a fresh one
    /// if the cache is empty or no longer usable for new sessions.
    ///
    /// This method is the reconnect path used by both warm-up and per-request
    /// server selection. The flow is intentionally exact:
    ///
    /// 1. check the cached connection without taking the per-server connect lock
    /// 2. if it is still usable for new sessions, return it immediately
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
    /// If the cached connection has learned that the server does not support
    /// TACACS+ single-connection reuse (or has later withdrawn that support for
    /// graceful shutdown), [`UpstreamConnection::is_usable_for_new_sessions`]
    /// returns `false` and the next IPC request reconnects instead of trying to
    /// reuse the drained connection.
    ///
    /// This method does not notify IPC clients directly; callers translate any
    /// returned error into a retriable
    /// [`tacacsrs_agent_client::ServiceError`] for
    /// the affected IPC request.
    async fn ensure_connection(&self, index: usize) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let existing_conn = self.servers[index].connection.read().await.clone();
        if let Some(existing) = existing_conn {
            if existing.is_usable_for_new_sessions().await {
                log::debug!(
                    "Reusing cached upstream connection for {}",
                    self.servers[index].server.socket_address()
                );
                return Ok(existing);
            }

            log::debug!(
                "Cached upstream connection for {} is no longer usable for new sessions; reconnecting",
                self.servers[index].server.socket_address()
            );
        }

        let reconnect_generation = self.servers[index]
            .completed_connect_attempts
            .load(Ordering::Acquire);
        let _connect_guard = self.servers[index].connect_lock.lock().await;

        let existing_conn = self.servers[index].connection.read().await.clone();
        if let Some(existing) = existing_conn {
            if existing.is_usable_for_new_sessions().await {
                log::debug!(
                    "Reusing cached upstream connection for {} after waiting on another reconnect",
                    self.servers[index].server.socket_address()
                );
                return Ok(existing);
            }
        }

        if self.servers[index]
            .completed_connect_attempts
            .load(Ordering::Acquire)
            != reconnect_generation
        {
            log::debug!(
                "Skipping duplicate reconnect to {}; another attempt already completed",
                self.servers[index].server.socket_address(),
            );
            bail!(
                "Another reconnect attempt for TACACS+ server {} already completed for this request wave",
                self.servers[index].server.socket_address()
            );
        }

        log::debug!(
            "Opening upstream connection to {}",
            self.servers[index].server.socket_address()
        );
        match self.connector.connect(&self.servers[index].server).await {
            Ok(connection) => {
                log::info!(
                    "Upstream connection to {} established successfully",
                    self.servers[index].server.socket_address(),
                );
                *self.servers[index].connection.write().await = Some(Arc::clone(&connection));
                self.servers[index]
                    .completed_connect_attempts
                    .fetch_add(1, Ordering::AcqRel);
                Ok(connection)
            }
            Err(error) => {
                log::warn!(
                    "Failed to connect to upstream TACACS+ server {}: {error:#}",
                    self.servers[index].server.socket_address(),
                );
                *self.servers[index].connection.write().await = None;
                self.servers[index]
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
    async fn note_failure(&self, index: usize) {
        // Keep request-time failure recording ordered with reconnect attempts
        // so a waiter that is about to reconnect observes the cleared cache
        // before it decides whether it must establish a fresh connection.
        let _connect_guard = self.servers[index].connect_lock.lock().await;
        *self.servers[index].connection.write().await = None;
        let mut active_index = self.active_index.write().await;
        if *active_index == index {
            let next_index = (index + 1) % self.servers.len();
            log::info!(
                "Failing over new IPC sessions from {} to {}",
                self.servers[index].server.socket_address(),
                self.servers[next_index].server.socket_address()
            );
            *active_index = next_index;
        }
    }

    /// Waits for all IPC client handlers to complete after the listener has
    /// stopped accepting new connections.
    pub(super) async fn wait_for_active_clients(&self) {
        self.client_tracker.wait_for_zero().await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use tacacsrs_config::TacacsPlusServer;
    use tokio::sync::Notify;

    use super::ServiceState;
    use super::super::test_support::{
        BlockingConnection, BlockingConnector, ExclusiveSessionConnector, FakeConnection,
        FakeConnector, SingleSessionConnector, build_request,
    };
    use crate::upstream::UpstreamConnector;

    fn test_server(address: &str) -> TacacsPlusServer {
        let (host, port) = match address.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(49)),
            None => (address.to_owned(), 49),
        };
        tacacsrs_config::TacacsPlusServer {
            name: address.to_owned(),
            server_type: tacacsrs_config::TacacsPlusServerType::ACCOUNTING,
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

        let state = ServiceState::new(
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

        let state = ServiceState::new(
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

        let state = Arc::new(ServiceState::new(
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

    #[tokio::test]
    async fn test_non_single_connection_is_reconnected_for_next_request() {
        let connector = Arc::new(SingleSessionConnector {
            address: "server-a:49".to_owned(),
            connect_attempts: AtomicUsize::new(0),
        });

        let state = ServiceState::new(
            vec![test_server("server-a:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
        );

        let first = state.bind_server_for_new_session().await.unwrap();
        first
            .connection
            .send_accounting(&build_request())
            .await
            .unwrap();

        let second = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(second.connection.server_address(), connector.address);
        assert_eq!(connector.connect_attempts.load(Ordering::Relaxed), 2);
    }

    // -----------------------------------------------------------------------
    // ClientTracker / drain-wait tests
    // -----------------------------------------------------------------------

    #[tokio::test]
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
            ServiceState::new(vec![test_server("server:49")], connector, Duration::from_secs(60));

        // No requests in flight — drain should return immediately.
        tokio::time::timeout(Duration::from_millis(100), state.wait_for_active_clients())
            .await
            .expect("wait_for_active_clients should return immediately with no active clients");
    }

    #[tokio::test]
    async fn test_drain_waits_for_in_flight_request_then_completes() {
        let release = Arc::new(Notify::new());
        let connector = Arc::new(BlockingConnector {
            connection: Arc::new(BlockingConnection {
                address: "server:49".to_owned(),
                release: Arc::clone(&release),
            }),
        });
        #[allow(unknown_lints, clippy::duration_suboptimal_units)]
        let state = Arc::new(ServiceState::new(
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
        let state = Arc::new(ServiceState::new(
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

    // -----------------------------------------------------------------------
    // Dedicated / shared connection mode tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_default_dedicated_connections_handle_concurrent_requests() {
        let connector = Arc::new(ExclusiveSessionConnector {
            address: "server:49".to_owned(),
            connect_attempts: AtomicUsize::new(0),
        });

        let state = Arc::new(ServiceState::new(
            vec![test_server("server:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
        ));
        state.warm_connections().await;

        // By default the service assumes non-single-connection, so every
        // request gets its own dedicated connection.  All 10 concurrent
        // requests should succeed without any retry logic.
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let state = Arc::clone(&state);
            tasks.push(tokio::spawn(async move {
                state.execute_accounting_request(build_request()).await
            }));
        }

        for task in tasks {
            let result = task.await.unwrap();
            assert!(result.is_ok(), "Request should succeed: {result:?}");
        }

        // 1 warm-up + 10 dedicated = 11 total connections.
        let total = connector.connect_attempts.load(Ordering::Relaxed);
        assert_eq!(total, 11, "Expected 1 warm-up + 10 dedicated connections");
    }

    #[tokio::test]
    async fn test_dedicated_exchange_upgrades_to_shared_connection() {
        let connection = Arc::new(FakeConnection {
            address: "server:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            "server:49".to_owned(),
            Arc::clone(&connection),
        )])));

        let state = ServiceState::new(
            vec![test_server("server:49")],
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
        );
        state.warm_connections().await;
        // warm-up: 1 connect

        // Flag starts false (pessimistic default).
        assert!(
            !state.servers[0]
                .single_connection_supported
                .load(Ordering::Relaxed),
            "single_connection_supported should start false"
        );

        // First request goes through the dedicated path. Because
        // FakeConnection reports SingleConnectionState::Supported, the
        // dedicated exchange returns single_connect_supported = true and
        // the state machine sets the per-server flag automatically.
        let result = state.execute_accounting_request(build_request()).await;
        assert!(result.is_ok());
        assert!(
            state.servers[0]
                .single_connection_supported
                .load(Ordering::Relaxed),
            "execute_with_dedicated_connection should set the flag when the server supports single-connection"
        );
        // warm-up (1) + dedicated send_accounting_dedicated (1) = 2
        assert_eq!(connector.connect_attempts_for("server:49").await, 2);

        // Second request should now take the shared cached-connection path,
        // reusing the warm-up connection without creating a new one.
        let result = state.execute_accounting_request(build_request()).await;
        assert!(result.is_ok());
        assert_eq!(
            connector.connect_attempts_for("server:49").await,
            2,
            "Shared path should reuse the cached connection (no additional connects)"
        );
    }
}
