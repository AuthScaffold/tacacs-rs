//! Client-side TACACS+ session provider.
//!
//! [`TacacsClient`] owns transport setup and the dedicated-to-shared
//! single-connection transition. Callers execute typed request/reply
//! descriptors or open a mutable packet conversation for transparent proxying.

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::{Mutex, RwLock};

use tacacsrs_protocol::accounting::reply::AccountingReply;
use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType, TacacsFlags, TacacsMajorVersion,
};
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_protocol::body::TacacsBodyTrait;

use crate::endpoint::PreparedEndpoint;
use crate::establish::ConnectPreflight;
use tacacsrs_protocol::exchange::FixedExchange;
use crate::exchange_error::FixedExchangeError;
use crate::runtime::MultiplexedConnection;
use crate::single_connect::SingleConnectionState;
use crate::session::{
    ClientConversation, ClientSession, DedicatedSession, ExpectedResponseHeader,
    SingleConnectPromotion,
};
use crate::transport::BoxedTransport;

mod lifecycle;
use lifecycle::ClientLifecycle;

/// Retires the shared connection when the last client or promotion owner drops.
#[derive(Default)]
pub(crate) struct SharedConnectionCache {
    pub(crate) slot: RwLock<Option<Arc<MultiplexedConnection>>>,
    pub(crate) generation: std::sync::atomic::AtomicU64,
    pub(crate) closed: std::sync::atomic::AtomicBool,
    retiring: std::sync::Mutex<Vec<Arc<MultiplexedConnection>>>,
}

impl SharedConnectionCache {
    fn retain_retiring(&self, connection: Arc<MultiplexedConnection>) {
        let mut retiring = self
            .retiring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retiring.retain(|connection| !connection.driver_finished());
        connection.disable_new_sessions();
        retiring.push(connection);
    }
}

impl Drop for SharedConnectionCache {
    fn drop(&mut self) {
        if let Some(connection) = self.slot.get_mut().take() {
            connection.disable_new_sessions();
        }
    }
}

/// A configured TACACS+ client that selects a dedicated or shared connection.
///
/// When the server configuration enables single-connection mode, the first
/// operation uses the configured preflight or a dedicated session to ask
/// the server for single-connection support. If the server echoes the
/// single-connect flag, the client upgrades and caches that connection for future
/// sessions. If single-connection mode is disabled in configuration or
/// unsupported by the server, future operations continue to use dedicated
/// connections.
///
/// [`Self::close`] permanently rejects new work. [`Self::close_and_join`]
/// drains existing sessions until its deadline, then forces transport closure
/// and joins owned tasks. Dropping the client requests immediate cleanup;
/// retained conversations do not extend the client's transport lifetime.
pub struct TacacsClient {
    endpoint: PreparedEndpoint,
    lifecycle: Arc<ClientLifecycle>,
    shared_connection: Arc<SharedConnectionCache>,
    single_connection_state: Arc<RwLock<SingleConnectionState>>,
    /// Serializes recovery when the cached shared connection is not available.
    ///
    /// The normal shared-session path does not take this lock. It only protects
    /// the slow path so concurrent callers do not all open probe
    /// connections after the same shared connection disconnects.
    shared_recovery_lock: Mutex<()>,
}

impl Drop for TacacsClient {
    fn drop(&mut self) {
        self.close();
        self.lifecycle.force_close_transports();
    }
}

impl TacacsClient {
    /// Creates a client without opening a network connection.
    fn from_prepared(endpoint: PreparedEndpoint) -> Self {
        let single_connection_enabled = endpoint.single_connection();
        Self {
            endpoint,
            lifecycle: Arc::default(),
            shared_connection: Arc::default(),
            single_connection_state: Arc::new(RwLock::new(if single_connection_enabled {
                SingleConnectionState::Initial
            } else {
                SingleConnectionState::NotSupported
            })),
            shared_recovery_lock: Mutex::new(()),
        }
    }

    /// Creates a client and optionally performs the configured preflight.
    ///
    /// When accounting watchdog preflight is enabled and the server
    /// configuration requests single-connection mode, the preflight request also
    /// performs capability discovery. A server that echoes the single-connect
    /// flag promotes the preflight transport into the cached shared connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the local certificate expired or the configured preflight fails.
    pub async fn connect_prepared(endpoint: PreparedEndpoint) -> anyhow::Result<Self> {
        if let Some(lifetime) = endpoint.prepared_credential_lifetime() {
            lifetime.check()?;
        }
        let connection = Self::from_prepared(endpoint);
        connection.run_preflight().await?;
        Ok(connection)
    }

    /// Creates a client session suitable for running TACACS+ flows.
    ///
    /// Session selection uses the server configuration and the observed
    /// single-connection state:
    ///
    /// ```text
    /// server.single_connection = false
    ///     |
    ///     v
    /// fresh dedicated session without single-connect flag
    ///
    /// server.single_connection = true
    ///     |
    ///     v
    /// accounting watchdog preflight, when enabled
    ///     |
    ///     +-- server echoes flag --------> [Supported]
    ///     |                                  |
    ///     |                                  v
    ///     |                         first create_session uses
    ///     |                         cached shared connection
    ///     |
    ///     +-- server omits flag ---------> [NotSupported]
    ///                                        |
    ///                                        v
    ///                              dedicated sessions only
    ///
    /// preflight disabled or shared recovery
    ///     |
    ///     v
    /// [Initial] ---- create_session ----> [Negotiating]
    ///     |                                  |
    ///     |                                  v
    ///     |                         dedicated session with
    ///     |                         SingleConnectPromotion
    ///     |
    ///     +-- server echoes flag --------> [Supported]
    ///     |                                  |
    ///     |                                  v
    ///     |                         use cached shared connection
    ///     |                                  |
    ///     |                                  +-- shared connection is still healthy
    ///     |                                  |       |
    ///     |                                  |       v
    ///     |                                  |   shared session
    ///     |                                  |
    ///     |                                  +-- shared connection disconnects
    ///     |                                          |
    ///     |                                          v
    ///     |                                 clear cache and return to [Initial]
    ///     |                                          |
    ///     |                                          v
    ///     |                                 next create_session renegotiates
    ///     |                                          |
    ///     |                                          +-- new backend echoes flag
    ///     |                                          |       |
    ///     |                                          |       v
    ///     |                                          |   [Supported]
    ///     |                                          |
    ///     |                                          +-- new backend omits flag
    ///     |                                                  |
    ///     |                                                  v
    ///     |                                              [NotSupported]
    ///     |
    ///     +-- server omits flag ---------> [NotSupported]
    ///                                        |
    ///                                        v
    ///                              dedicated sessions only
    /// ```
    ///
    /// After a hard disconnect from a cached shared connection, the next session
    /// probes again because a fresh TCP/TLS connection can connect to a different
    /// TACACS+ server. If that server is behind a load balancer and does not echo
    /// the single-connect flag, negotiation records `NotSupported` and this
    /// client uses dedicated connections for the rest of its lifetime.
    ///
    /// # Why the staged checks?
    ///
    /// This function re-checks state several times because other tasks can
    /// complete probes, lose shared streams, or mark single-connection mode as
    /// unsupported while this task waits. These checks do not repeat TCP
    /// connection attempts:
    ///
    /// 1. If configuration disables single-connection mode, create a fresh
    ///    dedicated connection.
    /// 2. If capability is unknown because preflight was disabled or a cached
    ///    shared connection disconnected, create one dedicated probe. This probe
    ///    determines whether a future shared connection is allowed.
    /// 3. If a probe is already active, use a fresh dedicated connection without a
    ///    promotion so concurrent callers do not race to publish conflicting
    ///    capability results.
    /// 4. If support is known, try the cached shared connection without taking
    ///    a lock. This is the hot path.
    /// 5. If the cached shared connection was rejected, re-read the state
    ///    because the rejection can reset the client to `Initial` or mark it
    ///    `NotSupported`.
    /// 6. Only the recovery path takes `shared_recovery_lock`, preventing many
    ///    concurrent callers from opening replacement probe connections.
    /// 7. After waiting for that lock, try the shared cache again because the
    ///    previous holder can restore it first.
    /// 8. If no shared session is available, perform the one required fallback:
    ///    dedicated-only for `NotSupported`, otherwise a new dedicated probe.
    ///
    /// # Errors
    ///
    /// Returns an error if no shared session can be created and a fresh
    /// dedicated transport cannot be opened.
    async fn create_session(&self) -> anyhow::Result<ClientSession> {
        self.create_session_for(None).await
    }

    async fn create_fixed_session(
        &self,
        expected: ExpectedResponseHeader,
    ) -> anyhow::Result<ClientSession> {
        self.create_session_for(Some(expected)).await
    }

    async fn create_session_for(
        &self,
        expected: Option<ExpectedResponseHeader>,
    ) -> anyhow::Result<ClientSession> {
        self.lifecycle.ensure_open()?;
        let operation = Box::pin(self.create_open_session(expected));
        let session = match self.endpoint.prepared_credential_lifetime() {
            Some(lifetime) => lifetime.run(operation).await?,
            None => operation.await?,
        };
        self.lifecycle.ensure_open()?;
        Ok(session.with_counters(self.endpoint.counters()))
    }

    async fn create_open_session(
        &self,
        expected: Option<ExpectedResponseHeader>,
    ) -> anyhow::Result<ClientSession> {
        if !self.endpoint.single_connection() {
            return Ok(ClientSession::dedicated(self.create_fresh_dedicated_session(None).await?));
        }

        // Stage 1: unknown capability and active negotiation are decided before
        // looking for a shared cache. Initial occurs only when preflight was
        // disabled or after a cached shared connection disconnected. Only Initial
        // can start the capability probe. Negotiating means another session already
        // owns it.
        match self.single_connection_state().await {
            SingleConnectionState::Initial => {
                return self.create_single_connect_negotiation_session().await;
            }
            SingleConnectionState::Negotiating | SingleConnectionState::NotSupported => {
                // Negotiating means another session already owns the probe.
                // NotSupported means that the probe denied support. In both
                // cases, open a fresh dedicated connection without promotion.
                return Ok(ClientSession::dedicated(
                    self.create_fresh_dedicated_session(None).await?,
                ));
            }
            SingleConnectionState::Supported => {}
        }

        // Stage 2: hot path. A confirmed, healthy shared connection can create
        // a session without serializing every caller on the recovery mutex.
        if let Some(session) = self.try_create_shared_session(expected).await {
            return Ok(session);
        }

        self.create_session_after_shared_miss(expected).await
    }

    /// Executes one fixed TACACS+ request/reply exchange.
    ///
    /// Networking assigns the session identifier and request sequence number,
    /// validates the complete reply header, and completes the underlying
    /// session on every success or error path.
    /// A configured client certificate bounds execution even without a caller deadline.
    ///
    /// # Errors
    ///
    /// Returns an error when session creation, request serialization, packet
    /// I/O, response validation, or reply parsing fails.
    pub async fn execute<Exchange>(&self, exchange: Exchange) -> anyhow::Result<Exchange::Reply>
    where
        Exchange: FixedExchange,
    {
        self.execute_classified(exchange)
            .await
            .map_err(FixedExchangeError::into_error)
    }

    /// Executes one fixed exchange and reports whether transmission started.
    ///
    /// # Errors
    ///
    /// Returns a classified error for session creation, request encoding,
    /// packet I/O, response validation, or reply parsing.
    pub async fn execute_classified<Exchange>(
        &self,
        exchange: Exchange,
    ) -> Result<Exchange::Reply, FixedExchangeError>
    where
        Exchange: FixedExchange,
    {
        if let Some(lifetime) = self.endpoint.prepared_credential_lifetime() {
            return self
                .execute_classified_until(exchange, lifetime.deadline)
                .await;
        }
        let expected =
            ExpectedResponseHeader::fixed(exchange.packet_type(), exchange.minor_version());
        let session = self
            .create_fixed_session(expected)
            .await
            .map_err(FixedExchangeError::not_sent)?;
        let result = execute_on_session(&session, exchange).await;
        session.complete().await;
        result
    }

    /// Executes a fixed exchange within one absolute request deadline.
    ///
    /// # Errors
    /// Returns a classified expiry before transmission or an unknown outcome
    /// after the exchange starts. The deadline includes session establishment.
    /// Client certificate expiry can shorten this deadline but cannot extend it.
    pub async fn execute_classified_until<Exchange>(
        &self,
        exchange: Exchange,
        deadline: crate::RequestDeadline,
    ) -> Result<Exchange::Reply, FixedExchangeError>
    where
        Exchange: FixedExchange,
    {
        let lifetime = self.endpoint.prepared_credential_lifetime();
        if let Some(lifetime) = lifetime {
            lifetime.check().map_err(FixedExchangeError::not_sent)?;
        }
        let deadline = lifetime.map_or(deadline, |lifetime| {
            crate::RequestDeadline::at(deadline.expires_at().min(lifetime.deadline.expires_at()))
        });
        let expected =
            ExpectedResponseHeader::fixed(exchange.packet_type(), exchange.minor_version());
        let session = deadline
            .run(self.create_fixed_session(expected))
            .await
            .map_err(FixedExchangeError::not_sent)?
            .map_err(FixedExchangeError::not_sent)?;
        deadline.check().map_err(FixedExchangeError::not_sent)?;
        let result = deadline
            .run(execute_on_session(&session, exchange))
            .await
            .map_err(FixedExchangeError::outcome_unknown)
            .and_then(std::convert::identity);
        let _completed = deadline.run(session.complete()).await;
        if let Some(lifetime) = lifetime {
            lifetime
                .check()
                .map_err(FixedExchangeError::outcome_unknown)?;
        }
        result
    }

    /// Opens a sequential packet conversation for transparent proxying and
    /// interactive TACACS+ authentication.
    ///
    /// # Errors
    ///
    /// Returns an error when a dedicated or shared session cannot be created.
    pub async fn open_conversation(&self) -> anyhow::Result<ClientConversation> {
        self.create_session().await.map(|session| {
            ClientConversation::new(session, self.endpoint.prepared_credential_lifetime())
        })
    }

    /// Stops the cached shared connection from accepting new sessions.
    ///
    /// Dedicated sessions are opened per operation and have no cached state to
    /// drain. If a shared connection exists, it is removed from the cache and told
    /// to reject future session creation while already-created sessions finish.
    pub async fn stop_accepting_new_sessions(&self) {
        let mut slot = self.shared_connection.slot.write().await;
        self.shared_connection
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        if let Some(connection) = slot.take() {
            self.shared_connection.retain_retiring(connection);
        }
    }

    /// Permanently rejects new work and cancels in-progress connection setup.
    ///
    /// Existing sessions can finish until [`Self::close_and_join`] forces cleanup.
    /// Closing is idempotent. A closed client cannot be reopened.
    pub fn close(&self) {
        self.lifecycle.close();
        self.shared_connection
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Closes the client, drains sessions, and joins setup, driver, and certificate-expiry tasks.
    ///
    /// At `deadline`, remaining transports close even if callers retain idle
    /// conversations or do not poll their I/O futures. Cancelled joins can be retried;
    /// the client remains closed. Final client drop also requests immediate cleanup.
    /// Certificate expiry can close a transport before this shutdown deadline.
    ///
    /// # Errors
    /// Returns a setup or driver task failure after completing other cleanup.
    /// This can include an I/O error from a driver already stopped by certificate expiry.
    pub async fn close_and_join(&self, deadline: crate::RequestDeadline) -> anyhow::Result<()> {
        self.close();
        self.stop_accepting_new_sessions().await;
        let setup_result = self.lifecycle.join_setups(deadline).await;
        let _drained = deadline.run(self.lifecycle.wait_for_transports()).await;
        let driver_result = self.retire_shared_until(deadline).await;
        self.lifecycle.force_close_transports();
        self.lifecycle.wait_for_transports().await;
        let expiry_result = self.lifecycle.join_expiries(deadline).await;
        setup_result.and(driver_result).and(expiry_result)
    }

    /// Retires and joins the currently cached and previously retired shared drivers.
    ///
    /// New sessions on those connections are disabled. Active sessions can drain
    /// until `deadline`; expiry aborts the drivers and waits for their cleanup.
    /// Cancellation retains the driver handles, so this method can be retried.
    ///
    /// This is shared-connection retirement, not client shutdown. Dedicated
    /// sessions and new session creation through this client remain permitted.
    /// The caller must quiesce new operations when using this as a shutdown step.
    /// Negotiations captured before retirement cannot repopulate the shared cache.
    ///
    /// # Errors
    /// Returns a driver I/O error or task failure after joining its task.
    pub async fn retire_shared_until(
        &self,
        deadline: crate::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.stop_accepting_new_sessions().await;
        let retiring = self
            .shared_connection
            .retiring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut failure = None;
        for connection in retiring {
            if let Err(error) = connection.close_and_join(deadline).await {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        self.shared_connection
            .retiring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|connection| !connection.driver_finished());
        failure.map_or(Ok(()), Err)
    }

    async fn create_session_after_shared_miss(
        &self,
        expected: Option<ExpectedResponseHeader>,
    ) -> anyhow::Result<ClientSession> {
        // Stage 3: a rejected shared connection returns the client to Initial
        // after transport loss. The next connection must negotiate again.
        match self.single_connection_state().await {
            SingleConnectionState::Initial => {
                return self.create_single_connect_negotiation_session().await;
            }
            SingleConnectionState::Negotiating | SingleConnectionState::NotSupported => {
                // Active negotiation and terminal denial both use new
                // dedicated connections without promotion.
                return Ok(ClientSession::dedicated(
                    self.create_fresh_dedicated_session(None).await?,
                ));
            }
            SingleConnectionState::Supported => {}
        }

        // Stage 4: slow-path serialization. Only one task can replace a
        // missing shared connection. Other tasks wait and then check again.
        let _shared_recovery_guard = self.shared_recovery_lock.lock().await;

        // Stage 5: another task can restore the shared cache while this task
        // waits for the recovery lock.
        if let Some(session) = self.try_create_shared_session(expected).await {
            return Ok(session);
        }

        // Stage 6: final fallback. This opens at most one fresh dedicated
        // session on this path. It opens a connection without a probe for
        // NotSupported, or a probe that can promote the completed connection.
        match self.single_connection_state().await {
            SingleConnectionState::NotSupported => {
                // Another task can record denial while this task waits
                // on recovery. Keep terminal NotSupported on fresh streams.
                Ok(ClientSession::dedicated(self.create_fresh_dedicated_session(None).await?))
            }
            SingleConnectionState::Negotiating => {
                Ok(ClientSession::dedicated(self.create_fresh_dedicated_session(None).await?))
            }
            SingleConnectionState::Initial | SingleConnectionState::Supported => {
                self.create_single_connect_negotiation_session().await
            }
        }
    }

    async fn create_single_connect_negotiation_session(&self) -> anyhow::Result<ClientSession> {
        let Some(promotion) = self.begin_single_connection_negotiation().await else {
            return Ok(ClientSession::dedicated(self.create_fresh_dedicated_session(None).await?));
        };

        Ok(ClientSession::dedicated(self.create_fresh_dedicated_session(Some(promotion)).await?))
    }

    async fn single_connection_state(&self) -> SingleConnectionState {
        *self.single_connection_state.read().await
    }

    /// Starts or joins single-connection negotiation for a dedicated session.
    ///
    /// The returned promotion object is the response callback for that session:
    /// it records whether the server echoed the single-connect flag and later
    /// receives the completed dedicated connection if promotion is safe.
    ///
    /// ```text
    /// [Initial] ---- begin ----> [Negotiating] -- returns promotion
    /// [Negotiating] -----------> [Negotiating] -- no promotion
    /// [Supported] ---- retry --> [Negotiating] -- returns promotion
    /// [NotSupported] ----------> [NotSupported] -- no promotion
    /// ```
    async fn begin_single_connection_negotiation(&self) -> Option<SingleConnectPromotion> {
        let mut state = self.single_connection_state.write().await;
        match *state {
            SingleConnectionState::NotSupported | SingleConnectionState::Negotiating => None,
            SingleConnectionState::Initial | SingleConnectionState::Supported => {
                *state = SingleConnectionState::Negotiating;
                Some(SingleConnectPromotion::new(
                    Arc::clone(&self.shared_connection),
                    Arc::clone(&self.single_connection_state),
                ))
            }
        }
    }

    async fn update_single_connection_state(&self, new_state: SingleConnectionState) {
        let mut state = self.single_connection_state.write().await;
        if *state == new_state {
            return;
        }

        log::info!(
            target: "tacacsrs_networking::client::single_connection_state",
            "Single-connection state changed from {:?} to {:?}",
            *state,
            new_state,
        );
        *state = new_state;
    }

    /// Updates the client state after the cached shared connection is rejected.
    ///
    /// A cached shared connection can stop accepting sessions for two different
    /// reasons:
    ///
    /// ```text
    /// cached shared connection cannot create a session
    ///     |
    ///     v
    /// inspect cached connection state
    ///     |
    ///     +-- [NotSupported]
    ///     |       |
    ///     |       v
    ///     |   first reply did not confirm single-connect support
    ///     |   mark client [NotSupported]
    ///     |   next session is dedicated without probing
    ///     |
    ///     +-- [Initial] / [Negotiating] / [Supported]
    ///             |
    ///             v
    ///         connection ended without a capability denial
    ///         mark client [Initial]
    ///         next session opens a dedicated probe
    ///             |
    ///             +-- new backend echoes flag --> cache shared connection
    ///             +-- new backend omits flag --> mark [NotSupported]
    /// ```
    ///
    /// The second path is the load-balancer-safe path: after a shared
    /// connection closes, the client does not assume that the next backend has the
    /// same single-connection capability.
    async fn update_state_after_shared_connection_rejection(
        &self,
        connection: &Arc<MultiplexedConnection>,
    ) {
        match connection.single_connection_state() {
            SingleConnectionState::NotSupported => {
                self.update_single_connection_state(SingleConnectionState::NotSupported)
                    .await;
            }
            SingleConnectionState::Initial
            | SingleConnectionState::Negotiating
            | SingleConnectionState::Supported => {
                self.update_single_connection_state(SingleConnectionState::Initial)
                    .await;
            }
        }
    }

    async fn try_create_shared_session(
        &self,
        expected: Option<ExpectedResponseHeader>,
    ) -> Option<ClientSession> {
        let connection = self.shared_connection.slot.read().await.clone()?;

        if !connection.can_create_sessions() {
            self.update_state_after_shared_connection_rejection(&connection)
                .await;
            self.clear_shared_connection(&connection).await;
            return None;
        }

        let session = match expected {
            Some(expected) => connection
                .create_fixed_session(expected)
                .map(ClientSession::shared_fixed),
            None => connection.create_session().map(ClientSession::shared),
        };

        match session {
            Ok(session) => Some(session),
            Err(error) => {
                log::debug!(
                    "Cached connection to TACACS+ server {} failed to create a session: {error:#}",
                    self.endpoint.address(),
                );
                self.update_state_after_shared_connection_rejection(&connection)
                    .await;
                self.clear_shared_connection(&connection).await;
                None
            }
        }
    }

    async fn clear_shared_connection(&self, connection: &Arc<MultiplexedConnection>) {
        let mut cached = self.shared_connection.slot.write().await;
        if cached
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, connection))
        {
            if let Some(connection) = cached.take() {
                self.shared_connection.retain_retiring(connection);
            }
        }
    }

    /// Creates a dedicated session from a newly opened transport.
    ///
    /// This is the normal dedicated path when configuration disables
    /// clients, concurrent callers while a single-connect probe is active, and
    /// clients whose initial single-connect probe reached terminal `NotSupported`.
    async fn create_fresh_dedicated_session(
        &self,
        single_connect_promotion: Option<SingleConnectPromotion>,
    ) -> anyhow::Result<DedicatedSession> {
        let transport = self.establish_stream().await?;

        Ok(self.create_dedicated_session_with_transport(transport, single_connect_promotion))
    }

    fn create_dedicated_session_with_transport(
        &self,
        transport: BoxedTransport,
        single_connect_promotion: Option<SingleConnectPromotion>,
    ) -> DedicatedSession {
        let obfuscation_key = self
            .endpoint
            .obfuscation_key
            .as_ref()
            .map(tacacsrs_secrets::SecretBytes::expose_secret);
        DedicatedSession::new(transport, obfuscation_key, single_connect_promotion)
    }

    async fn run_preflight(&self) -> anyhow::Result<()> {
        match self.endpoint.options.preflight() {
            ConnectPreflight::Disabled => Ok(()),
            ConnectPreflight::AccountingWatchdog => self.send_accounting_watchdog_preflight().await,
        }
    }

    async fn send_accounting_watchdog_preflight(&self) -> anyhow::Result<()> {
        let reply = self
            .execute(AccountingWatchdogExchange(accounting_watchdog_preflight_request()))
            .await?;

        match reply.status {
            TacacsAccountingStatus::TacPlusAcctStatusSuccess => Ok(()),
            status => anyhow::bail!("TACACS+ accounting WATCHDOG preflight failed: {status:?}"),
        }
    }

    async fn establish_stream(&self) -> anyhow::Result<BoxedTransport> {
        self.lifecycle.establish(self.endpoint.clone()).await
    }
}

struct AccountingWatchdogExchange(AccountingRequest);

impl FixedExchange for AccountingWatchdogExchange {
    type Reply = AccountingReply;

    fn packet_type(&self) -> tacacsrs_protocol::enumerations::TacacsType {
        tacacsrs_protocol::enumerations::TacacsType::TacPlusAccounting
    }

    fn minor_version(&self) -> tacacsrs_protocol::enumerations::TacacsMinorVersion {
        tacacsrs_protocol::enumerations::TacacsMinorVersion::TacacsPlusMinorVerDefault
    }

    fn encode_request(&self) -> anyhow::Result<Vec<u8>> {
        self.0.to_bytes()
    }

    fn decode_reply(self, body: &[u8]) -> anyhow::Result<Self::Reply> {
        AccountingReply::from_bytes(body)
    }
}

async fn execute_on_session<Exchange>(
    session: &ClientSession,
    exchange: Exchange,
) -> Result<Exchange::Reply, FixedExchangeError>
where
    Exchange: FixedExchange,
{
    const REQUEST_SEQUENCE_NUMBER: u8 = 1;
    const RESPONSE_SEQUENCE_NUMBER: u8 = 2;

    let session_id = session.session_id();
    let packet_type = exchange.packet_type();
    let minor_version = exchange.minor_version();
    let body = exchange
        .encode_request()
        .map_err(FixedExchangeError::not_sent)?;
    let length = u32::try_from(body.len())
        .context("fixed TACACS+ request body exceeds the protocol length field")
        .map_err(FixedExchangeError::not_sent)?;
    let request = Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version,
            tacacs_type: packet_type,
            seq_no: REQUEST_SEQUENCE_NUMBER,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id,
            length,
        },
        body,
    )
    .map_err(FixedExchangeError::not_sent)?;

    let response = session
        .fixed_round_trip(request)
        .await
        .map_err(FixedExchangeError::outcome_unknown)?;
    let header = response.header();

    if header.session_id != session_id
        || header.seq_no != RESPONSE_SEQUENCE_NUMBER
        || header.tacacs_type != packet_type
        || header.major_version != TacacsMajorVersion::TacacsPlusMajor1
        || header.minor_version != minor_version
    {
        return Err(FixedExchangeError::outcome_unknown(anyhow::anyhow!(
            "unexpected fixed TACACS+ response header: session_id={:#x}, seq_no={}, type={}, version={:?}.{:?}; expected session_id={:#x}, seq_no={}, type={}, version={:?}.{:?}",
            header.session_id,
            header.seq_no,
            header.tacacs_type,
            header.major_version,
            header.minor_version,
            session_id,
            RESPONSE_SEQUENCE_NUMBER,
            packet_type,
            TacacsMajorVersion::TacacsPlusMajor1,
            minor_version,
        )));
    }

    session.record_terminal_reply(&response);
    let reply = exchange
        .decode_reply(response.body())
        .map_err(FixedExchangeError::outcome_unknown)?;
    Ok(reply)
}

fn accounting_watchdog_preflight_request() -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::WATCHDOG,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNotSet,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: "tacacsrs-preflight".to_owned(),
        port: "tacacsrs-networking".to_owned(),
        rem_address: "127.0.0.1".to_owned(),
        args: vec![
            "task_id=tacacsrs-preflight-watchdog".to_owned(),
            "service=tacacsrs-networking".to_owned(),
            "preflight=true".to_owned(),
            "watchdog=true".to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn operational_counters_cover_shared_sessions_and_connection_outcomes() {
        use super::*;
        use tokio::net::TcpListener;
        use crate::{PacketReader, PacketReadResult, PacketWriter, PacketWriteResult};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            true,
            None,
            ConnectOptions::default(),
        );
        let counters = endpoint.counters();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for status in [
                TacacsAccountingStatus::TacPlusAcctStatusError,
                TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            ] {
                let PacketReadResult::Success(request) =
                    PacketReader::new(None).read_packet(&mut stream).await
                else {
                    panic!("request must decode");
                };
                let body = AccountingReply {
                    status,
                    server_msg: String::new(),
                    data: String::new(),
                }
                .to_bytes()
                .unwrap();
                let mut header = request.header().clone();
                header.seq_no += 1;
                header.flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG
                    | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
                header.length = u32::try_from(body.len()).unwrap();
                let packet = Packet::new(header, body).unwrap();
                assert!(matches!(
                    PacketWriter::new(None)
                        .write_packet(&mut stream, packet)
                        .await,
                    PacketWriteResult::Success
                ));
            }
        });
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        for _ in 0..2 {
            client
                .execute(AccountingWatchdogExchange(accounting_watchdog_preflight_request()))
                .await
                .unwrap();
        }
        peer.await.unwrap();
        if let Err(error) = client
            .close_and_join(
                crate::RequestDeadline::after(std::time::Duration::from_secs(1)).unwrap(),
            )
            .await
        {
            assert!(
                error.chain().any(|cause| cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)),
                "unexpected shutdown error: {error:#}"
            );
        }
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.connection_opens, 1);
        assert_eq!(snapshot.messages_sent, 2);
        assert_eq!(snapshot.messages_received, 2);
        assert_eq!(snapshot.errors_received, 1);
        assert_eq!(snapshot.sessions, 2);
        assert_eq!(snapshot.connection_closes, 1);
        assert_eq!(snapshot.connection_aborts, 0);
        assert_eq!(snapshot.connection_failures, 0);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            ConnectOptions::default(),
        );
        let failed = endpoint.counters();
        drop(listener);
        assert!(crate::establish::establish_stream(&endpoint).await.is_err());
        assert_eq!(failed.snapshot().connection_opens, 1);
        assert_eq!(failed.snapshot().connection_failures, 1);
        assert_eq!(failed.snapshot().messages_sent, 0);
    }

    #[tokio::test]
    async fn invalid_psk_fails_before_client_construction() {
        let result = crate::PreparedEndpoint::tcp(
            "127.0.0.1:1",
            false,
            None,
            crate::ConnectOptions::default(),
        )
        .with_psk("client", b"too-short", crate::PskHash::Sha256, &[], None);
        let Err(error) = result else {
            panic!("invalid material must fail before the lazy client is returned");
        };
        assert!(format!("{error:#}").contains("PSK key must be at least 16 bytes"));
    }

    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use tacacsrs_protocol::accounting::reply::AccountingReply;
    use tacacsrs_protocol::accounting::request::AccountingRequest;
    use tacacsrs_protocol::enumerations::{
        TacacsAccountingFlags, TacacsAccountingStatus, TacacsFlags, TacacsMajorVersion,
        TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_protocol::header::Header;
    use tacacsrs_protocol::packet::{Packet, PacketTrait};
    use tacacsrs_protocol::body::TacacsBodyTrait;

    use super::{TacacsClient, accounting_watchdog_preflight_request};
    use crate::PreparedEndpoint;
    use crate::codec::{PacketReadResult, PacketReader};
    use crate::establish::{ConnectOptions, ConnectPreflight};
    use tacacsrs_protocol::exchange::FixedExchange;
    use crate::single_connect::SingleConnectionState;

    struct TestAccountingExchange(AccountingRequest);

    impl FixedExchange for TestAccountingExchange {
        type Reply = AccountingReply;

        fn packet_type(&self) -> TacacsType {
            TacacsType::TacPlusAccounting
        }

        fn minor_version(&self) -> TacacsMinorVersion {
            TacacsMinorVersion::TacacsPlusMinorVerDefault
        }

        fn encode_request(&self) -> anyhow::Result<Vec<u8>> {
            self.0.to_bytes()
        }

        fn decode_reply(self, body: &[u8]) -> anyhow::Result<Self::Reply> {
            AccountingReply::from_bytes(body)
        }
    }

    fn server_template() -> PreparedEndpoint {
        PreparedEndpoint::tcp("10.0.0.1:49", true, None, ConnectOptions::default())
    }

    fn test_packet(session_id: u32, seq_no: u8, flags: TacacsFlags) -> Packet {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no,
                flags,
                session_id,
                length: 0,
            },
            Vec::new(),
        )
        .unwrap()
    }

    fn accounting_success_reply(request: &Packet, flags: TacacsFlags) -> Packet {
        let reply = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: String::new(),
            data: String::new(),
        };
        let body = reply.to_bytes().unwrap();
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: request.header().seq_no.wrapping_add(1),
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | flags,
                session_id: request.header().session_id,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap()
    }

    fn spawn_accounting_server(
        listener: TcpListener,
        exchanges: usize,
        reply_flags: TacacsFlags,
    ) -> (mpsc::Receiver<Packet>, tokio::task::JoinHandle<()>) {
        let (request_sender, request_receiver) = mpsc::channel(exchanges);
        let server_task = tokio::spawn(async move {
            let mut connection_tasks = Vec::with_capacity(exchanges);
            for _ in 0..exchanges {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request_sender = request_sender.clone();
                connection_tasks.push(tokio::spawn(async move {
                    let reader = PacketReader::new(None);
                    let PacketReadResult::Success(packet) = reader.read_packet(&mut stream).await
                    else {
                        panic!("test server did not receive a valid TACACS+ packet");
                    };
                    let reply = accounting_success_reply(&packet, reply_flags);
                    stream.write_all(&reply.to_bytes()).await.unwrap();
                    request_sender.send(packet).await.unwrap();
                }));
            }

            drop(request_sender);
            for connection_task in connection_tasks {
                connection_task.await.unwrap();
            }
        });

        (request_receiver, server_task)
    }

    fn spawn_single_stream_accounting_server(
        listener: TcpListener,
        exchanges: usize,
        reply_flags: TacacsFlags,
    ) -> (mpsc::Receiver<Packet>, tokio::task::JoinHandle<()>) {
        spawn_single_stream_accounting_server_with_reply_flags(
            listener,
            vec![reply_flags; exchanges],
        )
    }

    fn spawn_single_stream_accounting_server_with_reply_flags(
        listener: TcpListener,
        reply_flags: Vec<TacacsFlags>,
    ) -> (mpsc::Receiver<Packet>, tokio::task::JoinHandle<()>) {
        let exchanges = reply_flags.len();
        let (request_sender, request_receiver) = mpsc::channel(exchanges);
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let reader = PacketReader::new(None);

            for flags in reply_flags {
                let PacketReadResult::Success(packet) = reader.read_packet(&mut stream).await
                else {
                    panic!("test server did not receive a valid TACACS+ packet");
                };
                let reply = accounting_success_reply(&packet, flags);
                stream.write_all(&reply.to_bytes()).await.unwrap();
                request_sender.send(packet).await.unwrap();
            }
        });

        (request_receiver, server_task)
    }

    async fn receive_request(request_receiver: &mut mpsc::Receiver<Packet>) -> Packet {
        tokio::time::timeout(Duration::from_secs(1), request_receiver.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn run_session_exchange(session: &crate::session::ClientSession) {
        let session_id = session.session_id();
        session
            .send_packet(test_packet(session_id, 1, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG))
            .await
            .unwrap();
        session.receive_packet().await.unwrap();
    }

    #[tokio::test]
    async fn connect_with_disabled_preflight_does_not_open_transport() {
        let mut server = server_template();
        server.address = "127.0.0.1:1".to_owned();

        let client = TacacsClient::connect_prepared(server).await.unwrap();

        assert_eq!(client.single_connection_state().await, SingleConnectionState::Initial);
    }

    #[test]
    fn packet_obfuscation_key_uses_shared_secret_for_tls_servers() {
        let endpoint = PreparedEndpoint::tcp(
            "10.0.0.1:49",
            false,
            Some(tacacsrs_secrets::SecretBytes::new(b"legacy-secret".to_vec())),
            ConnectOptions::default(),
        )
        .with_certificate_tls("10.0.0.1", None, crate::CertificateTrust::Platform, None)
        .unwrap();
        assert_eq!(endpoint.obfuscation_key.unwrap().expose_secret(), b"legacy-secret");
    }

    #[tokio::test]
    async fn terminal_close_drains_dedicated_and_shared_conversations() {
        use tokio::io::AsyncReadExt;
        use crate::RequestDeadline;

        for shared in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = TacacsClient::connect_prepared(PreparedEndpoint::tcp(
                listener.local_addr().unwrap().to_string(),
                shared,
                None,
                ConnectOptions::default(),
            ))
            .await
            .unwrap();
            let mut conversation = client.open_conversation().await.unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            if shared {
                let request = test_packet(
                    conversation.session_id().unwrap(),
                    1,
                    TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                );
                let exchange = conversation.round_trip(request);
                let reply = async {
                    let PacketReadResult::Success(request) =
                        PacketReader::new(None).read_packet(&mut peer).await
                    else {
                        panic!("expected request");
                    };
                    peer.write_all(
                        &accounting_success_reply(
                            &request,
                            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                        )
                        .to_bytes(),
                    )
                    .await
                    .unwrap();
                };
                let (result, ()) = tokio::join!(exchange, reply);
                result.unwrap();
                conversation.complete().await;
                conversation = client.open_conversation().await.unwrap();
            }
            let closing =
                client.close_and_join(RequestDeadline::after(Duration::from_secs(5)).unwrap());
            tokio::pin!(closing);
            assert!(futures::poll!(&mut closing).is_pending());
            assert!(client.open_conversation().await.is_err());
            conversation.complete().await;
            tokio::time::timeout(Duration::from_secs(1), closing)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shorter_terminal_join_closes_transport_for_all_waiters() {
        use tokio::io::AsyncReadExt;
        use crate::RequestDeadline;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TacacsClient::connect_prepared(PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            ConnectOptions::default(),
        ))
        .await
        .unwrap();
        let _conversation = client.open_conversation().await.unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let longer =
            client.close_and_join(RequestDeadline::after(Duration::from_secs(60)).unwrap());
        tokio::pin!(longer);
        assert!(futures::poll!(&mut longer).is_pending());
        client
            .close_and_join(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        longer.await.unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn terminal_close_releases_a_parked_dedicated_read_and_rejects_new_work() {
        use tokio::io::AsyncReadExt;
        use crate::{RequestDeadline, TransmissionState};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            ConnectOptions::default(),
        );
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let session = client.create_session().await.unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        session
            .send_packet(test_packet(
                session.session_id(),
                1,
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            ))
            .await
            .unwrap();
        assert!(matches!(
            PacketReader::new(None).read_packet(&mut peer).await,
            PacketReadResult::Success(_)
        ));
        let read = session.receive_packet();
        tokio::pin!(read);
        assert!(futures::poll!(&mut read).is_pending());
        tokio::time::timeout(
            Duration::from_secs(1),
            client.close_and_join(RequestDeadline::after(Duration::ZERO).unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(read.await.is_err());
        assert!(client.open_conversation().await.is_err());
        let error = client
            .execute_classified(TestAccountingExchange(accounting_watchdog_preflight_request()))
            .await
            .unwrap_err();
        assert_eq!(error.transmission_state(), TransmissionState::NotSent);
        client
            .close_and_join(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn terminal_close_cancels_stalled_tls_setup_without_polling_its_caller() {
        use tokio::io::AsyncReadExt;
        use crate::{CertificateTrust, RequestDeadline};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            ConnectOptions::default(),
        )
        .with_certificate_tls("localhost", None, CertificateTrust::Platform, None)
        .unwrap();
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let opening = client.open_conversation();
        tokio::pin!(opening);
        assert!(futures::poll!(&mut opening).is_pending());
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut hello = [0; 4096];
        assert!(peer.read(&mut hello).await.unwrap() > 0);
        tokio::time::timeout(
            Duration::from_secs(1),
            client.close_and_join(RequestDeadline::after(Duration::from_secs(5)).unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        let mut remaining = Vec::new();
        peer.read_to_end(&mut remaining).await.unwrap();
        assert!(opening.await.is_err());
        assert!(client.open_conversation().await.is_err());
    }

    #[tokio::test]
    async fn client_drop_prevents_an_old_negotiation_from_starting_a_driver() {
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_requests, server_task) = spawn_single_stream_accounting_server(
            listener,
            1,
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        );
        let client = TacacsClient::connect_prepared(PreparedEndpoint::tcp(
            address.to_string(),
            true,
            None,
            ConnectOptions::default(),
        ))
        .await
        .unwrap();
        let session = client.create_session().await.unwrap();
        run_session_exchange(&session).await;
        let cache = Arc::clone(&client.shared_connection);
        drop(client);
        session.complete().await;
        assert!(cache.slot.read().await.is_none());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn dropping_client_closes_retained_idle_dedicated_conversation() {
        use tokio::io::AsyncReadExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TacacsClient::connect_prepared(PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            ConnectOptions::default(),
        ))
        .await
        .unwrap();
        let mut conversation = client.open_conversation().await.unwrap();
        let session_id = conversation.session_id().unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        drop(client);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(conversation
            .round_trip(test_packet(session_id, 1, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG))
            .await
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_terminal_join_remains_closed_and_can_be_retried() {
        use tokio::io::AsyncReadExt;
        use crate::RequestDeadline;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TacacsClient::connect_prepared(PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            ConnectOptions::default(),
        ))
        .await
        .unwrap();
        let _conversation = client.open_conversation().await.unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        {
            let closing =
                client.close_and_join(RequestDeadline::after(Duration::from_secs(10)).unwrap());
            tokio::pin!(closing);
            assert!(futures::poll!(&mut closing).is_pending());
        }
        assert!(client.open_conversation().await.is_err());
        client
            .close_and_join(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn shared_retirement_drains_active_session_and_releases_driver() {
        use std::sync::Arc;
        use tokio::io::AsyncReadExt;
        use crate::runtime::MultiplexedConnection;

        let client = TacacsClient::from_prepared(server_template());
        let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
        let session = connection.create_session().unwrap();
        let (transport, mut peer) = tokio::io::duplex(256);
        let (reader, writer) = tokio::io::split(transport);
        connection.run_with_halves(reader, writer);
        *client.shared_connection.slot.write().await = Some(connection.clone());
        let retirement = client
            .retire_shared_until(crate::RequestDeadline::after(Duration::from_secs(1)).unwrap());
        tokio::pin!(retirement);
        assert!(futures::poll!(&mut retirement).is_pending());
        assert!(connection.create_session().is_err());
        session.complete();
        retirement.await.unwrap();
        assert!(connection.driver_finished());
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_shared_retirement_can_be_retried_without_losing_drivers() {
        use std::sync::Arc;
        use tokio::io::AsyncReadExt;
        use crate::runtime::MultiplexedConnection;

        let client = TacacsClient::from_prepared(server_template());
        for _cycle in 0..8 {
            let connection =
                Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
            let session = connection.create_session().unwrap();
            let (transport, mut peer) = tokio::io::duplex(256);
            let (reader, writer) = tokio::io::split(transport);
            connection.run_with_halves(reader, writer);
            *client.shared_connection.slot.write().await = Some(connection.clone());
            {
                let retirement = client.retire_shared_until(
                    crate::RequestDeadline::after(Duration::from_secs(10)).unwrap(),
                );
                tokio::pin!(retirement);
                assert!(futures::poll!(&mut retirement).is_pending());
            }
            client
                .retire_shared_until(crate::RequestDeadline::after(Duration::ZERO).unwrap())
                .await
                .unwrap();
            assert!(connection.driver_finished());
            assert!(session.receive_packet().await.is_err());
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            assert!(client.shared_connection.retiring.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn shared_retirement_prevents_late_promotion() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_requests, server_task) = spawn_single_stream_accounting_server(
            listener,
            1,
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        );
        let mut endpoint = server_template();
        endpoint.address = address.to_string();
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let session = client.create_session().await.unwrap();
        run_session_exchange(&session).await;
        client
            .retire_shared_until(crate::RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        session.complete().await;
        assert!(client.shared_connection.slot.read().await.is_none());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn dropping_client_retires_idle_cached_transport() {
        use std::sync::Arc;

        use tokio::io::AsyncReadExt;

        use crate::runtime::MultiplexedConnection;

        let client = TacacsClient::from_prepared(server_template());
        let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
        let (transport, mut peer) = tokio::io::duplex(256);
        let (reader, writer) = tokio::io::split(transport);
        connection.run_with_halves(reader, writer);
        *client.shared_connection.slot.write().await = Some(connection);

        drop(client);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0; 1]))
                .await
                .expect("the last cache owner must retire the transport")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn dropping_client_preserves_active_session_until_completion() {
        use std::sync::Arc;

        use tokio::io::AsyncReadExt;

        use crate::runtime::MultiplexedConnection;

        let client = TacacsClient::from_prepared(server_template());
        let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
        let session = connection.create_session().unwrap();
        let (transport, mut peer) = tokio::io::duplex(256);
        let (reader, writer) = tokio::io::split(transport);
        connection.run_with_halves(reader, writer);
        *client.shared_connection.slot.write().await = Some(Arc::clone(&connection));
        drop(client);
        assert!(connection.create_session().is_err());
        let mut byte = [0; 1];
        let read = peer.read(&mut byte);
        tokio::pin!(read);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(read.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(session);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), read)
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn executes_fixed_exchange_over_dedicated_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) =
            spawn_accounting_server(listener, 1, TacacsFlags::empty());

        let mut server = server_template();
        server.address = listener_address.to_string();
        server.single_connection = false;
        let client = TacacsClient::connect_prepared(server).await.unwrap();

        let reply = client
            .execute(TestAccountingExchange(accounting_watchdog_preflight_request()))
            .await
            .unwrap();
        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);

        let request = receive_request(&mut request_receiver).await;
        assert_eq!(request.header().seq_no, 1);
        assert_eq!(request.header().tacacs_type, TacacsType::TacPlusAccounting);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn expired_exchange_does_not_open_a_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut endpoint = server_template();
        endpoint.address = listener.local_addr().unwrap().to_string();
        endpoint.single_connection = false;
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let error = client
            .execute_classified_until(
                TestAccountingExchange(accounting_watchdog_preflight_request()),
                crate::RequestDeadline::after(Duration::ZERO).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.transmission_state(), crate::TransmissionState::NotSent);
        let accept = listener.accept();
        tokio::pin!(accept);
        assert!(futures::poll!(&mut accept).is_pending());
    }

    #[tokio::test]
    async fn deadline_classifies_stalled_tls_and_sent_requests() {
        use tokio::io::AsyncReadExt;
        use crate::{
            CertificateTrust, PacketReader, PacketReadResult, RequestDeadline, TransmissionState,
        };

        for tls in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut endpoint = server_template();
            endpoint.address = listener.local_addr().unwrap().to_string();
            endpoint.single_connection = false;
            if tls {
                endpoint = endpoint
                    .with_certificate_tls("localhost", None, CertificateTrust::Platform, None)
                    .unwrap();
            }
            let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
            let deadline = RequestDeadline::after(Duration::from_millis(200)).unwrap();
            let exchange = client.execute_classified_until(
                TestAccountingExchange(accounting_watchdog_preflight_request()),
                deadline,
            );
            let peer = async {
                let (mut peer, _) = listener.accept().await.unwrap();
                if !tls {
                    assert!(matches!(
                        PacketReader::new(None).read_packet(&mut peer).await,
                        PacketReadResult::Success(_)
                    ));
                }
                let mut remaining = Vec::new();
                peer.read_to_end(&mut remaining).await.unwrap();
                if tls {
                    assert!(!remaining.is_empty(), "the client must start its TLS handshake");
                }
            };
            let (result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(exchange, peer)
            })
            .await
            .unwrap();
            assert_eq!(
                result.unwrap_err().transmission_state(),
                if tls {
                    TransmissionState::NotSent
                } else {
                    TransmissionState::OutcomeUnknown
                }
            );
        }
    }

    #[tokio::test]
    async fn accounting_watchdog_preflight_establishes_shared_connection_when_echoed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) = spawn_single_stream_accounting_server(
            listener,
            2,
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        );

        let mut server = server_template();
        server.address = listener_address.to_string();
        server.options =
            ConnectOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog);
        let client = TacacsClient::connect_prepared(server).await.unwrap();

        let preflight_packet = receive_request(&mut request_receiver).await;
        let preflight_request = AccountingRequest::from_packet(&preflight_packet).unwrap();
        assert!(preflight_request
            .flags
            .contains(TacacsAccountingFlags::WATCHDOG));
        assert!(preflight_packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        assert_eq!(client.single_connection_state().await, SingleConnectionState::Supported);
        assert!(client.shared_connection.slot.read().await.is_some());

        let reply = tokio::time::timeout(
            Duration::from_secs(1),
            client.execute(TestAccountingExchange(accounting_watchdog_preflight_request())),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);

        let real_session_packet = receive_request(&mut request_receiver).await;
        assert!(!real_session_packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn accounting_watchdog_preflight_records_not_supported_when_not_echoed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) =
            spawn_accounting_server(listener, 2, TacacsFlags::empty());

        let mut server = server_template();
        server.address = listener_address.to_string();
        server.options =
            ConnectOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog);
        let client = TacacsClient::connect_prepared(server).await.unwrap();

        let preflight_packet = receive_request(&mut request_receiver).await;
        let preflight_request = AccountingRequest::from_packet(&preflight_packet).unwrap();
        assert!(preflight_request
            .flags
            .contains(TacacsAccountingFlags::WATCHDOG));
        assert_eq!(preflight_request.user, "tacacsrs-preflight");
        assert!(preflight_request
            .args
            .contains(&"task_id=tacacsrs-preflight-watchdog".to_owned()));
        assert!(preflight_packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        assert_eq!(client.single_connection_state().await, SingleConnectionState::NotSupported);
        assert!(client.shared_connection.slot.read().await.is_none());

        let session = client.create_session().await.unwrap();
        run_session_exchange(&session).await;
        session.complete().await;

        let real_session_packet = receive_request(&mut request_receiver).await;
        assert!(!real_session_packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn confirmed_single_connection_ignores_later_unset_reply_flags() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) =
            spawn_single_stream_accounting_server_with_reply_flags(
                listener,
                vec![
                    TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                    TacacsFlags::empty(),
                    TacacsFlags::empty(),
                ],
            );

        let mut server = server_template();
        server.address = listener_address.to_string();
        let client = TacacsClient::from_prepared(server);

        for _ in 0..3 {
            let reply = tokio::time::timeout(
                Duration::from_secs(1),
                client.execute(TestAccountingExchange(accounting_watchdog_preflight_request())),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        }

        let first_request = receive_request(&mut request_receiver).await;
        assert!(first_request
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        for _ in 0..2 {
            let later_request = receive_request(&mut request_receiver).await;
            assert!(!later_request
                .header()
                .flags
                .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        }
        assert_eq!(client.single_connection_state().await, SingleConnectionState::Supported);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn unsupported_single_connect_probe_makes_later_sessions_dedicated_only() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) =
            spawn_accounting_server(listener, 2, TacacsFlags::empty());

        let mut server = server_template();
        server.address = listener_address.to_string();
        let client = TacacsClient::from_prepared(server);

        let first_session = client.create_session().await.unwrap();
        run_session_exchange(&first_session).await;
        first_session.complete().await;
        let first_request = receive_request(&mut request_receiver).await;
        assert!(first_request
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));

        assert_eq!(client.single_connection_state().await, SingleConnectionState::NotSupported);

        let second_session = client.create_session().await.unwrap();
        run_session_exchange(&second_session).await;
        second_session.complete().await;
        let second_request = receive_request(&mut request_receiver).await;
        assert!(!second_request
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));

        server_task.await.unwrap();
        assert_eq!(client.single_connection_state().await, SingleConnectionState::NotSupported);
    }

    #[tokio::test]
    async fn stale_negotiation_attempt_uses_dedicated_stream_after_not_supported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) =
            spawn_accounting_server(listener, 1, TacacsFlags::empty());

        let mut server = server_template();
        server.address = listener_address.to_string();
        let client = TacacsClient::from_prepared(server);

        client
            .update_single_connection_state(SingleConnectionState::NotSupported)
            .await;

        let session = client
            .create_single_connect_negotiation_session()
            .await
            .unwrap();
        run_session_exchange(&session).await;
        session.complete().await;

        let request = receive_request(&mut request_receiver).await;
        assert!(!request
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_session_during_negotiation_does_not_start_second_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) =
            spawn_accounting_server(listener, 2, TacacsFlags::empty());

        let mut server = server_template();
        server.address = listener_address.to_string();
        let client = TacacsClient::from_prepared(server);

        let first_session = client.create_session().await.unwrap();
        assert_eq!(client.single_connection_state().await, SingleConnectionState::Negotiating);

        let second_session = client.create_session().await.unwrap();
        run_session_exchange(&second_session).await;
        second_session.complete().await;
        let second_request = receive_request(&mut request_receiver).await;

        assert!(!second_request
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        assert_eq!(client.single_connection_state().await, SingleConnectionState::Negotiating);

        run_session_exchange(&first_session).await;
        first_session.complete().await;
        let first_request = receive_request(&mut request_receiver).await;
        assert!(first_request
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        server_task.await.unwrap();
    }
}
