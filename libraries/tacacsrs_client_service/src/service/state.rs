//! Internal state machine for IPC request routing and TACACS+ server failover.
//!
//! [`ServiceState`] is shared by all listener tasks. It owns the currently
//! preferred server index, cached upstream connections, and the active-client
//! drain tracking used during graceful shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use anyhow::bail;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, Notify, RwLock};

use crate::codec::{read_message, write_message};
use crate::protocol::{ServiceError, ServiceRequest, ServiceResponse};
use crate::upstream::{UpstreamConnection, UpstreamConnector};

/// Shared runtime state for all IPC client handlers spawned by the listener.
///
/// Each incoming IPC connection calls into this type exactly once. The state
/// then binds that request to an upstream TACACS+ server, executes the
/// operation, and records any failover information needed for future requests.
pub(super) struct ServiceState {
    servers: Vec<ServerState>,
    connector: Arc<dyn UpstreamConnector>,
    active_index: RwLock<usize>,
    preferred_probe_interval: std::time::Duration,
    client_tracker: Arc<ClientTracker>,
}

struct ServerState {
    address: String,
    connection: RwLock<Option<Arc<dyn UpstreamConnection>>>,
    connect_lock: Mutex<()>,
    completed_connect_attempts: AtomicU64,
}

pub(super) struct BoundServer {
    pub(super) index: usize,
    pub(super) connection: Arc<dyn UpstreamConnection>,
}

/// Tracks how many client handlers are currently executing so shutdown can stop
/// accepting new work first and then wait for in-flight requests to complete.
#[derive(Default)]
struct ClientTracker {
    active_clients: AtomicUsize,
    drained: Notify,
}

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
        server_addresses: Vec<String>,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
    ) -> Self {
        Self {
            servers: server_addresses
                .into_iter()
                .map(|address| ServerState {
                    address,
                    connection: RwLock::new(None),
                    connect_lock: Mutex::new(()),
                    completed_connect_attempts: AtomicU64::new(0),
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
                        self.servers[index].address
                    );
                }
            }
        }

        log::warn!(
            "Startup did not find a responsive TACACS+ server; requests will retry on demand"
        );
    }

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
                    continue;
                }

                match state.ensure_connection(0).await {
                    Ok(connection) => {
                        log::info!(
                            "Preferred TACACS+ server {} recovered; routing new sessions back to it",
                            connection.server_address()
                        );
                        *state.active_index.write().await = 0;
                    }
                    Err(error) => {
                        log::debug!("Preferred TACACS+ server probe failed: {error}");
                    }
                }
            }
        })
    }

    /// Handles one IPC client connection from first framed request through the
    /// final framed response.
    ///
    /// The current protocol allows exactly one request per IPC connection in
    /// this service path, so the method reads one [`ServiceRequest`], binds the
    /// session to an upstream server, and writes one [`ServiceResponse`].
    ///
    /// Unknown or unsupported request kinds do not reach the dispatch match
    /// below: deserialization in [`read_message`] fails first because
    /// [`ServiceRequest`] is a tagged enum with `deny_unknown_fields`.
    pub(super) async fn handle_client<S>(&self, mut stream: S) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _client_guard = self.client_tracker.start_guard();
        let request: ServiceRequest = read_message(&mut stream).await?;
        let response = match self.bind_server_for_new_session().await {
            Ok(bound_server) => self.execute_request(bound_server, request).await,
            Err(error) => {
                ServiceResponse::Error(ServiceError::new(error.to_string()).retriable(true))
            }
        };

        write_message(&mut stream, &response).await
    }

    /// Executes a decoded IPC request against the upstream server already bound
    /// to this IPC session.
    ///
    /// The match is exhaustive over [`ServiceRequest`]. If a future request
    /// variant is added, Rust will require this handler to define how that new
    /// operation should behave. Unsupported request kinds therefore fail at
    /// decode time today and become compile-time work when the protocol grows.
    async fn execute_request(
        &self,
        bound_server: BoundServer,
        request: ServiceRequest,
    ) -> ServiceResponse {
        match request {
            ServiceRequest::Accounting(accounting) => {
                match bound_server.connection.send_accounting(&accounting).await {
                    Ok(response) => ServiceResponse::Accounting(response),
                    Err(error) => {
                        self.note_failure(bound_server.index).await;
                        ServiceResponse::Error(
                            ServiceError::new(error.to_string())
                                .with_server(bound_server.connection.server_address())
                                .retriable(true),
                        )
                    }
                }
            }
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
                        self.servers[index].address
                    );
                    self.note_failure(index).await;
                }
            }
        }

        bail!("No responsive TACACS+ servers are currently available")
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
    /// returned error into a retriable [`crate::protocol::ServiceError`] for
    /// the affected IPC request.
    async fn ensure_connection(&self, index: usize) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        if let Some(existing) = self.servers[index].connection.read().await.clone() {
            if existing.is_usable_for_new_sessions().await {
                log::debug!(
                    "Reusing cached upstream connection for {}",
                    self.servers[index].address
                );
                return Ok(existing);
            }

            log::debug!(
                "Cached upstream connection for {} is no longer usable for new sessions; reconnecting",
                self.servers[index].address
            );
        }

        let reconnect_generation = self.servers[index]
            .completed_connect_attempts
            .load(Ordering::Acquire);
        let _connect_guard = self.servers[index].connect_lock.lock().await;

        if let Some(existing) = self.servers[index].connection.read().await.clone() {
            if existing.is_usable_for_new_sessions().await {
                log::debug!(
                    "Reusing cached upstream connection for {} after waiting on another reconnect",
                    self.servers[index].address
                );
                return Ok(existing);
            }
        }

        if self.servers[index]
            .completed_connect_attempts
            .load(Ordering::Acquire)
            != reconnect_generation
        {
            bail!(
                "Another reconnect attempt for TACACS+ server {} already completed for this request wave",
                self.servers[index].address
            );
        }

        log::debug!("Opening upstream connection to {}", self.servers[index].address);
        match self.connector.connect(&self.servers[index].address).await {
            Ok(connection) => {
                *self.servers[index].connection.write().await = Some(Arc::clone(&connection));
                self.servers[index]
                    .completed_connect_attempts
                    .fetch_add(1, Ordering::AcqRel);
                Ok(connection)
            }
            Err(error) => {
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
                self.servers[index].address,
                self.servers[next_index].address
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
