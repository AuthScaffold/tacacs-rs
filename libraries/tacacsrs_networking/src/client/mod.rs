//! Preferred client-side TACACS+ session provider.
//!
//! [`TacacsClient`] owns transport setup and the dedicated-to-shared
//! single-connection transition. It deliberately stops at
//! [`ClientSessionFlowIoTrait`](tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait):
//! callers obtain a session I/O object and then
//! run request/reply flows from `tacacsrs-flows` on top of it.

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::{Mutex, RwLock};

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_flow_abstractions::accounting::{build_accounting_packet, parse_accounting_reply};
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType, TacacsFlags, TacacsMajorVersion,
};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use crate::establish::{self, ConnectOptions, ConnectPreflight};
use crate::exchange::FixedExchange;
use crate::runtime::MultiplexedConnection;
use crate::single_connect::SingleConnectionState;
use crate::session::{ClientSession, DedicatedSession, SharedSession, SingleConnectPromotion};
use crate::transport::BoxedTransport;

/// A configured TACACS+ client connection that transparently chooses between
/// dedicated one-shot streams and a cached multiplexed connection.
///
/// When the server configuration enables single-connection mode, the first
/// operation either uses the configured preflight or a dedicated session to ask
/// the server for single-connection support. If the server echoes the
/// single-connect flag, that transport is upgraded and cached for future
/// sessions. If single-connection mode is disabled in configuration or
/// unsupported by the server, future operations continue to use dedicated
/// streams.
pub struct TacacsClient {
    server: TacacsPlusServer,
    options: ConnectOptions,
    shared_connection: Arc<RwLock<Option<Arc<MultiplexedConnection>>>>,
    single_connection_state: Arc<RwLock<SingleConnectionState>>,
    /// Serializes recovery when the cached shared connection is unavailable.
    ///
    /// The normal shared-session path does not take this lock. It only protects
    /// the slow path so a burst of concurrent callers does not all open probe
    /// connections after the same shared stream disconnects.
    shared_recovery_lock: Mutex<()>,
}

impl TacacsClient {
    /// Creates a client connection without opening the network transport yet.
    #[must_use]
    fn new(server: TacacsPlusServer, options: ConnectOptions) -> Self {
        let single_connection_enabled = server.single_connection;
        Self {
            server,
            options,
            shared_connection: Arc::new(RwLock::new(None)),
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
    /// Returns an error if TCP connection, TLS negotiation, or PSK setup fails.
    pub async fn connect(
        server: TacacsPlusServer,
        options: ConnectOptions,
    ) -> anyhow::Result<Self> {
        let connection = Self::new(server, options);
        connection.run_preflight().await?;
        Ok(connection)
    }

    /// Creates a client session suitable for running TACACS+ flows.
    ///
    /// Session selection follows the server configuration and the observed
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
    ///     |                         cached shared stream
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
    ///     |                         use cached shared stream
    ///     |                                  |
    ///     |                                  +-- shared stream is still healthy
    ///     |                                  |       |
    ///     |                                  |       v
    ///     |                                  |   shared session
    ///     |                                  |
    ///     |                                  +-- shared stream disconnects
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
    /// After a hard disconnect from a cached shared stream, the next session
    /// probes again because a fresh TCP/TLS connection may land on a different
    /// server. If that new server is behind a load balancer and does not echo
    /// the single-connect flag, negotiation records `NotSupported` and this
    /// client uses dedicated streams for the rest of its lifetime.
    ///
    /// # Why the staged checks?
    ///
    /// This function re-checks state several times because other tasks can
    /// complete probes, lose shared streams, or mark single-connection mode as
    /// unsupported while this task is waiting. Those checks are not repeated TCP
    /// connect attempts:
    ///
    /// 1. If configuration disables single-connection mode, create a fresh
    ///    dedicated stream.
    /// 2. If capability is unknown because preflight was disabled or a cached
    ///    shared stream disconnected, create the one dedicated probe that will
    ///    answer whether a future shared stream is allowed.
    /// 3. If a probe is already active, use a fresh dedicated stream without a
    ///    promotion so concurrent callers do not race to publish conflicting
    ///    capability results.
    /// 4. If support is known, try the cached shared connection without taking
    ///    a lock. This is the hot path.
    /// 5. If the cached shared connection was rejected, re-read the state
    ///    because the rejection may have reset the client to `Initial` or marked
    ///    it `NotSupported`.
    /// 6. Only the recovery path takes `shared_recovery_lock`, preventing many
    ///    callers from opening replacement probe connections at the same time.
    /// 7. After waiting for that lock, try the shared cache again because the
    ///    previous holder may already have restored it.
    /// 8. If no shared session is available, perform the one required fallback:
    ///    dedicated-only for `NotSupported`, otherwise a new dedicated probe.
    ///
    /// # Errors
    ///
    /// Returns an error if no shared session can be created and a fresh
    /// dedicated transport cannot be opened.
    pub async fn create_session(&self) -> anyhow::Result<ClientSession> {
        if !self.server.single_connection {
            return Ok(ClientSession::dedicated(self.create_fresh_dedicated_session(None).await?));
        }

        // Stage 1: unknown capability and active negotiation are decided before
        // looking for a shared cache. Initial only happens when preflight was
        // disabled or after a cached shared stream disconnected. Only Initial
        // may start the capability probe; Negotiating means another session
        // already owns it.
        match self.single_connection_state().await {
            SingleConnectionState::Initial => {
                return self.create_single_connect_negotiation_session().await;
            }
            SingleConnectionState::Negotiating | SingleConnectionState::NotSupported => {
                // Negotiating means another session already owns the probe.
                // NotSupported means that probe denied capability. In both
                // cases, open a fresh dedicated stream without promotion.
                return Ok(ClientSession::dedicated(
                    self.create_fresh_dedicated_session(None).await?,
                ));
            }
            SingleConnectionState::Supported => {}
        }

        // Stage 2: hot path. A confirmed, healthy shared connection can create
        // a session without serializing every caller on the recovery mutex.
        if let Some(session) = self.try_create_shared_session().await {
            return Ok(ClientSession::shared(session));
        }

        self.create_session_after_shared_miss().await
    }

    /// Executes one fixed TACACS+ request/reply exchange.
    ///
    /// Networking assigns the session identifier and request sequence number,
    /// validates the complete reply header, and completes the underlying
    /// session on every success or error path.
    ///
    /// # Errors
    ///
    /// Returns an error when session creation, request serialization, packet
    /// I/O, response validation, or reply parsing fails.
    pub async fn execute<Exchange>(&self, exchange: Exchange) -> anyhow::Result<Exchange::Reply>
    where
        Exchange: FixedExchange,
    {
        let session = self.create_session().await?;
        let result = execute_on_session(&session, exchange).await;
        session.complete().await;
        result
    }

    /// Stops the cached shared connection from accepting new sessions.
    ///
    /// Dedicated sessions are opened per operation and have no cached state to
    /// drain. If a shared stream exists, it is removed from the cache and told
    /// to reject future session creation while already-created sessions finish.
    pub async fn stop_accepting_new_sessions(&self) {
        let connection = self.shared_connection.write().await.take();
        if let Some(connection) = connection {
            connection.disable_new_sessions().await;
        }
    }

    async fn create_session_after_shared_miss(&self) -> anyhow::Result<ClientSession> {
        // Stage 3: the failed shared attempt may have changed client state. For
        // example, a graceful server shutdown becomes NotSupported, while a hard
        // disconnect returns to Initial so the next connection can negotiate.
        match self.single_connection_state().await {
            SingleConnectionState::Initial => {
                return self.create_single_connect_negotiation_session().await;
            }
            SingleConnectionState::Negotiating | SingleConnectionState::NotSupported => {
                // Active negotiation and terminal denial both use fresh
                // dedicated streams without promotion.
                return Ok(ClientSession::dedicated(
                    self.create_fresh_dedicated_session(None).await?,
                ));
            }
            SingleConnectionState::Supported => {}
        }

        // Stage 4: slow-path serialization. Only one task should replace a
        // missing shared connection; other tasks wait and then re-check.
        let _shared_recovery_guard = self.shared_recovery_lock.lock().await;

        // Stage 5: another task may have restored the shared cache while this
        // one waited for the recovery lock.
        if let Some(session) = self.try_create_shared_session().await {
            return Ok(ClientSession::shared(session));
        }

        // Stage 6: final fallback. This opens at most one fresh dedicated
        // session on this path: either no-probe dedicated for NotSupported, or
        // a probe that can promote the completed stream to shared.
        match self.single_connection_state().await {
            SingleConnectionState::NotSupported => {
                // Another task may have recorded denial while this task waited
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
    /// it observes whether the server echoed the single-connect flag and later
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
            "Single connection state changed from {:?} to {:?}",
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
    /// cached shared stream cannot create a session
    ///     |
    ///     v
    /// inspect cached connection state
    ///     |
    ///     +-- [NotSupported]
    ///     |       |
    ///     |       v
    ///     |   server removed the single-connect flag
    ///     |   mark client [NotSupported]
    ///     |   next session is dedicated without probing
    ///     |
    ///     +-- [Initial] / [Negotiating] / [Supported]
    ///             |
    ///             v
    ///         stream ended without a capability denial
    ///         mark client [Initial]
    ///         next session opens a dedicated probe
    ///             |
    ///             +-- new backend echoes flag --> cache shared stream
    ///             +-- new backend omits flag --> mark [NotSupported]
    /// ```
    ///
    /// The second path is the load-balancer-safe path: after a shared
    /// connection drops, the client does not assume the next backend has the
    /// same single-connection capability.
    async fn update_state_after_shared_connection_rejection(
        &self,
        connection: &Arc<MultiplexedConnection>,
    ) {
        match connection.single_connection_state().await {
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

    async fn try_create_shared_session(&self) -> Option<SharedSession> {
        let connection = self.shared_connection.read().await.clone()?;

        if !connection.can_create_sessions().await {
            self.update_state_after_shared_connection_rejection(&connection)
                .await;
            self.clear_shared_connection(&connection).await;
            return None;
        }

        let session = connection.create_session().await;

        match session {
            Ok(session) => Some(session),
            Err(error) => {
                log::debug!(
                    "Cached TACACS+ connection to {} could not create a session: {error:#}",
                    self.server.socket_address(),
                );
                self.update_state_after_shared_connection_rejection(&connection)
                    .await;
                self.clear_shared_connection(&connection).await;
                None
            }
        }
    }

    async fn clear_shared_connection(&self, connection: &Arc<MultiplexedConnection>) {
        let mut cached = self.shared_connection.write().await;
        if cached
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, connection))
        {
            *cached = None;
        }
    }

    /// Creates a dedicated session from a newly opened transport.
    ///
    /// This is the steady-state dedicated path for configuration-disabled
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
        let obfuscation_key = packet_obfuscation_key(&self.server);
        DedicatedSession::new(transport, obfuscation_key.as_deref(), single_connect_promotion)
    }

    async fn run_preflight(&self) -> anyhow::Result<()> {
        match self.options.preflight() {
            ConnectPreflight::Disabled => Ok(()),
            ConnectPreflight::AccountingWatchdog => self.send_accounting_watchdog_preflight().await,
        }
    }

    async fn send_accounting_watchdog_preflight(&self) -> anyhow::Result<()> {
        let single_connect_promotion = self.begin_single_connection_negotiation().await;
        let session = self
            .create_fresh_dedicated_session(single_connect_promotion)
            .await?;
        let request = accounting_watchdog_preflight_request();
        let sequence_number = session.next_sequence_number().await;
        let packet = build_accounting_packet(
            session.session_id(),
            sequence_number,
            &request,
            TacacsFlags::empty(),
        )?;

        session.send_packet(packet).await?;
        let response = session.receive_packet().await?;
        let reply = parse_accounting_reply(&response)?;

        match reply.status {
            TacacsAccountingStatus::TacPlusAcctStatusSuccess => {
                session.complete().await;
                Ok(())
            }
            status => anyhow::bail!("TACACS+ accounting watchdog preflight failed: {status:?}"),
        }
    }

    async fn establish_stream(&self) -> anyhow::Result<BoxedTransport> {
        let address = self.server.socket_address();
        establish::establish_stream(&self.server, &self.options)
            .await
            .with_context(|| format!("Failed to connect to {address}"))
    }
}

async fn execute_on_session<Exchange>(
    session: &ClientSession,
    exchange: Exchange,
) -> anyhow::Result<Exchange::Reply>
where
    Exchange: FixedExchange,
{
    const REQUEST_SEQUENCE_NUMBER: u8 = 1;
    const RESPONSE_SEQUENCE_NUMBER: u8 = 2;

    let session_id = session.session_id();
    let packet_type = exchange.packet_type();
    let minor_version = exchange.minor_version();
    let body = exchange.encode_request()?;
    let length = u32::try_from(body.len())
        .context("fixed TACACS+ request body exceeds the protocol length field")?;
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
    )?;

    session.send_packet(request).await?;
    let response = session.receive_packet().await?;
    let header = response.header();

    if header.session_id != session_id
        || header.seq_no != RESPONSE_SEQUENCE_NUMBER
        || header.tacacs_type != packet_type
        || header.major_version != TacacsMajorVersion::TacacsPlusMajor1
        || header.minor_version != minor_version
    {
        anyhow::bail!(
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
        );
    }

    exchange.decode_reply(response.body())
}

fn packet_obfuscation_key(server: &TacacsPlusServer) -> Option<Vec<u8>> {
    server.obfuscation_key()
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
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerBuilder, TacacsPlusServerType};
    use tacacsrs_messages::accounting::reply::AccountingReply;
    use tacacsrs_messages::accounting::request::AccountingRequest;
    use tacacsrs_messages::enumerations::{
        TacacsAccountingFlags, TacacsAccountingStatus, TacacsFlags, TacacsMajorVersion,
        TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::{Packet, PacketTrait};
    use tacacsrs_messages::traits::TacacsBodyTrait;

    use super::{TacacsClient, accounting_watchdog_preflight_request, packet_obfuscation_key};
    use crate::codec::{PacketReadResult, PacketReader, PacketReaderTrait};
    use crate::establish::{ConnectOptions, ConnectPreflight};
    use crate::exchange::FixedExchange;
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

    fn server_template() -> TacacsPlusServer {
        TacacsPlusServer {
            name: "test".to_owned(),
            server_type: TacacsPlusServerType::all(),
            address: "10.0.0.1".to_owned(),
            port: 49,
            shared_secret: None,
            timeout: 5,
            single_connection: true,
            domain_name: None,
            sni_enabled: None,
            client_identity: None,
            server_authentication: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        }
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
        let (request_sender, request_receiver) = mpsc::channel(exchanges);
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let reader = PacketReader::new(None);

            for _ in 0..exchanges {
                let PacketReadResult::Success(packet) = reader.read_packet(&mut stream).await
                else {
                    panic!("test server did not receive a valid TACACS+ packet");
                };
                let reply = accounting_success_reply(&packet, reply_flags);
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
        server.address = "127.0.0.1".to_owned();
        server.port = 1;

        let client = TacacsClient::connect(server, ConnectOptions::default())
            .await
            .unwrap();

        assert_eq!(client.single_connection_state().await, SingleConnectionState::Initial);
    }

    #[test]
    fn packet_obfuscation_key_uses_shared_secret_for_tls_servers() {
        let server =
            TacacsPlusServerBuilder::new("test", TacacsPlusServerType::all(), "10.0.0.1", 49)
                .with_tls_server_authentication()
                .with_shared_secret_alongside_tls("legacy-secret")
                .build();

        assert_eq!(packet_obfuscation_key(&server), Some(b"legacy-secret".to_vec()));
    }

    #[tokio::test]
    async fn executes_fixed_exchange_over_dedicated_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) =
            spawn_accounting_server(listener, 1, TacacsFlags::empty());

        let mut server = server_template();
        server.address = listener_address.ip().to_string();
        server.port = listener_address.port();
        server.single_connection = false;
        let client = TacacsClient::connect(server, ConnectOptions::default())
            .await
            .unwrap();

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
    async fn accounting_watchdog_preflight_establishes_shared_connection_when_echoed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) = spawn_single_stream_accounting_server(
            listener,
            2,
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        );

        let mut server = server_template();
        server.address = listener_address.ip().to_string();
        server.port = listener_address.port();
        let client = TacacsClient::connect(
            server,
            ConnectOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog),
        )
        .await
        .unwrap();

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
        assert!(client.shared_connection.read().await.is_some());

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
        server.address = listener_address.ip().to_string();
        server.port = listener_address.port();
        let client = TacacsClient::connect(
            server,
            ConnectOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog),
        )
        .await
        .unwrap();

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
        assert!(client.shared_connection.read().await.is_none());

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
    async fn unsupported_single_connect_probe_makes_later_sessions_dedicated_only() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (mut request_receiver, server_task) =
            spawn_accounting_server(listener, 2, TacacsFlags::empty());

        let mut server = server_template();
        server.address = listener_address.ip().to_string();
        server.port = listener_address.port();
        let client = TacacsClient::new(server, ConnectOptions::default());

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
        server.address = listener_address.ip().to_string();
        server.port = listener_address.port();
        let client = TacacsClient::new(server, ConnectOptions::default());

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
        server.address = listener_address.ip().to_string();
        server.port = listener_address.port();
        let client = TacacsClient::new(server, ConnectOptions::default());

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
