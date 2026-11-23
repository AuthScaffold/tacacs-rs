//! Scripted plain-TCP TACACS+ upstream server with injectable faults.
//!
//! The server echoes the request user name in `server_msg` of every reply,
//! including error replies. A client can therefore detect a reply that the
//! proxy delivered to the wrong session. A replaceable fault plan selects the
//! behavior of each request from its operation and its per-operation index.
//!
//! PAP authentication completes in one round trip. ASCII authentication asks
//! for the password with `GETPASS` and completes with the `CONTINUE` packet.
//! The fixture can also send malformed replies: wrong session identifiers,
//! wrong sequence numbers, invalid headers, oversized lengths, unknown
//! statuses, and bodies that use the wrong shared secret.
//!
//! [`Upstream::start_tls`] serves the same behavior over TLS 1.3. Packets then
//! use the cleartext framing of RFC 9887 and the fixture records failed
//! handshakes. The fixture also records the source address of each connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use openssl::ssl::{Ssl, SslContext};
use tacacsrs_networking::{PacketReadResult, PacketReader, PacketWriteResult, PacketWriter};
use tacacsrs_protocol::accounting::reply::AccountingReply;
use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::accounting::reply::ACCOUNTING_REPLY_STATUS_OFFSET;
use tacacsrs_protocol::authentication::continue_packet::AuthenticationContinue;
use tacacsrs_protocol::authentication::reply::{
    AUTHENTICATION_REPLY_STATUS_OFFSET, AuthenticationReply,
};
use tacacsrs_protocol::authentication::start::AuthenticationStart;
use tacacsrs_protocol::authorization::reply::{AUTHORIZATION_REPLY_STATUS_OFFSET, AuthorizationReply};
use tacacsrs_protocol::authorization::request::AuthorizationRequest;
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
    TacacsAuthenticationType, TacacsAuthorizationStatus, TacacsFlags, TacacsType,
};
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_secrets::SecretBytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

static UPSTREAM_KEY: OnceLock<String> = OnceLock::new();
static GOOD_PASSWORD: OnceLock<Vec<u8>> = OnceLock::new();

/// Returns a random shared secret for the daemon and this upstream fixture.
pub(crate) fn upstream_key() -> &'static str {
    UPSTREAM_KEY.get_or_init(random_fixture_secret)
}

/// Returns the password that the fixture accepts for PAP and ASCII authentication.
pub(crate) fn good_password() -> &'static [u8] {
    GOOD_PASSWORD
        .get_or_init(|| random_fixture_secret().into_bytes())
        .as_slice()
}

fn random_fixture_secret() -> String {
    let mut bytes = [0; 32];
    openssl::rand::rand_bytes(&mut bytes).expect("OpenSSL must generate test fixture secrets");
    openssl::base64::encode_block(&bytes)
}

/// Response of the fixture to a single-connection request from the daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SingleConnect {
    /// Set the flag in the first reply and keep the connection for more sessions.
    Accept,
    /// Clear the flag in the reply and close the connection after one session.
    Decline,
}

/// Operation of one upstream request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Authentication = 0,
    Authorization = 1,
    Accounting = 2,
}

impl Kind {
    pub(crate) const ALL: [Self; 3] = [Self::Authentication, Self::Authorization, Self::Accounting];

    const fn from_type(tacacs_type: TacacsType) -> Self {
        match tacacs_type {
            TacacsType::TacPlusAuthentication => Self::Authentication,
            TacacsType::TacPlusAuthorisation => Self::Authorization,
            TacacsType::TacPlusAccounting => Self::Accounting,
        }
    }
}

/// One request as the fault plan sees it.
#[derive(Clone, Debug)]
pub(crate) struct Request {
    pub(crate) kind: Kind,
    /// Zero-based arrival index of this request within its operation.
    pub(crate) index: u64,
    /// True for an authentication `CONTINUE` packet of an ASCII login.
    pub(crate) continuation: bool,
    /// User name of the request, or of the login that a `CONTINUE` belongs to.
    pub(crate) user: String,
}

/// Behavior of the fixture for one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    /// Send the normal reply immediately.
    None,
    /// Send the normal reply after a delay.
    Delay(Duration),
    /// Send a type-correct protocol `ERROR` reply.
    Error,
    /// Close the TCP connection without a reply.
    Close,
    /// Keep the connection open and never reply.
    Hang,
    /// Send half of a reply header and then stall.
    PartialHeader,
    /// Replace the status byte of the normal reply.
    Status(u8),
    /// Send the normal reply with a different session identifier.
    WrongSession,
    /// Send the normal reply with a sequence number that skips ahead.
    WrongSequence,
    /// Send a header that announces a body above the RFC 8907 limit, then stall.
    OversizedLength,
    /// Send a header with an unknown major version, then stall.
    BadHeader,
    /// Obfuscate the normal reply with a different shared secret.
    BadKey,
}

impl Fault {
    const fn counter(self) -> Option<usize> {
        match self {
            Self::None | Self::Delay(_) => None,
            Self::Error => Some(0),
            Self::Close => Some(1),
            Self::Hang => Some(2),
            Self::PartialHeader => Some(3),
            Self::Status(_) => Some(4),
            Self::WrongSession => Some(5),
            Self::WrongSequence => Some(6),
            Self::OversizedLength => Some(7),
            Self::BadHeader => Some(8),
            Self::BadKey => Some(9),
        }
    }
}

pub(crate) type Plan = Arc<dyn Fn(&Request) -> Fault + Send + Sync>;

/// Returns a plan that answers every request normally.
pub(crate) fn healthy() -> Plan {
    Arc::new(|_| Fault::None)
}

#[derive(Default)]
struct PerKind([AtomicU64; 3]);

impl PerKind {
    fn add(&self, kind: Kind) -> u64 {
        self.0[kind as usize].fetch_add(1, Ordering::SeqCst)
    }

    fn get(&self, kind: Kind) -> u64 {
        self.0[kind as usize].load(Ordering::SeqCst)
    }

    fn total(&self) -> u64 {
        Kind::ALL.iter().map(|kind| self.get(*kind)).sum()
    }
}

struct State {
    mode: SingleConnect,
    /// Obfuscation key. TLS connections use cleartext packets and no key.
    key: Option<SecretBytes>,
    tls: Option<SslContext>,
    peers: Mutex<Vec<SocketAddr>>,
    handshake_failures: AtomicU64,
    plan: Mutex<Plan>,
    received: PerKind,
    injected: [PerKind; 10],
    connections: AtomicU64,
    open_connections: AtomicUsize,
    in_flight: [AtomicUsize; 3],
    max_in_flight: [AtomicUsize; 3],
}

/// Running fixture. Dropping it stops the listener and every connection.
pub(crate) struct Upstream {
    address: SocketAddr,
    state: Arc<State>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

impl Upstream {
    pub(crate) async fn start(mode: SingleConnect) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self::serve(mode, listener, None)
    }

    /// Starts a fixture that accepts only TLS connections that `context` allows.
    pub(crate) async fn start_tls(mode: SingleConnect, context: SslContext) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self::serve(mode, listener, Some(context))
    }

    /// Starts a fixture on a fixed address, for example to restart a server.
    ///
    /// The bind retries for a short time because a dropped fixture releases
    /// its listener asynchronously.
    pub(crate) async fn start_on(mode: SingleConnect, address: SocketAddr) -> Self {
        let mut attempts = 0;
        loop {
            match TcpListener::bind(address).await {
                Ok(listener) => return Self::serve(mode, listener, None),
                Err(error) => {
                    attempts += 1;
                    assert!(attempts < 100, "could not bind {address} again: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn serve(mode: SingleConnect, listener: TcpListener, tls: Option<SslContext>) -> Self {
        let address = listener.local_addr().unwrap();
        let state = Arc::new(State {
            mode,
            key: tls.is_none().then(key),
            tls,
            peers: Mutex::new(Vec::new()),
            handshake_failures: AtomicU64::new(0),
            plan: Mutex::new(healthy()),
            received: PerKind::default(),
            injected: Default::default(),
            connections: AtomicU64::new(0),
            open_connections: AtomicUsize::new(0),
            in_flight: Default::default(),
            max_in_flight: Default::default(),
        });
        let stop = CancellationToken::new();
        let task = tokio::spawn(accept_loop(listener, Arc::clone(&state), stop.clone()));
        Self {
            address,
            state,
            stop,
            task,
        }
    }

    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Replaces the fault plan for requests that arrive after this call.
    pub(crate) fn set_plan(&self, plan: Plan) {
        *self.state.plan.lock().unwrap() = plan;
    }

    pub(crate) fn received_total(&self) -> u64 {
        self.state.received.total()
    }

    pub(crate) fn received(&self, kind: Kind) -> u64 {
        self.state.received.get(kind)
    }

    /// Returns the number of requests that received `fault`.
    pub(crate) fn injected(&self, fault: Fault) -> u64 {
        fault
            .counter()
            .map_or(0, |index| self.state.injected[index].total())
    }

    pub(crate) fn connections_accepted(&self) -> u64 {
        self.state.connections.load(Ordering::SeqCst)
    }

    pub(crate) fn mode(&self) -> SingleConnect {
        self.state.mode
    }

    pub(crate) fn open_connections(&self) -> usize {
        self.state.open_connections.load(Ordering::SeqCst)
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.state
            .in_flight
            .iter()
            .map(|value| value.load(Ordering::SeqCst))
            .sum()
    }

    pub(crate) fn max_in_flight(&self, kind: Kind) -> usize {
        self.state.max_in_flight[kind as usize].load(Ordering::SeqCst)
    }

    /// Returns the source address of every accepted TCP connection.
    pub(crate) fn peers(&self) -> Vec<SocketAddr> {
        self.state.peers.lock().unwrap().clone()
    }

    /// Returns the number of TLS handshakes that failed.
    pub(crate) fn handshake_failures(&self) -> u64 {
        self.state.handshake_failures.load(Ordering::SeqCst)
    }
}

async fn accept_loop(listener: TcpListener, state: Arc<State>, stop: CancellationToken) {
    loop {
        let accepted = tokio::select! {
            () = stop.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        state.connections.fetch_add(1, Ordering::SeqCst);
        state.peers.lock().unwrap().push(peer);
        let connection = stop.child_token();
        let Some(context) = state.tls.clone() else {
            tokio::spawn(serve_connection(stream, Arc::clone(&state), connection));
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut stream =
                tokio_openssl::SslStream::new(Ssl::new(&context).unwrap(), stream).unwrap();
            let accepted = tokio::select! {
                () = connection.cancelled() => return,
                accepted = Pin::new(&mut stream).accept() => accepted,
            };
            if accepted.is_err() {
                state.handshake_failures.fetch_add(1, Ordering::SeqCst);
                return;
            }
            serve_connection(stream, state, connection).await;
        });
    }
}

enum Output {
    Packet(Packet),
    Raw(Vec<u8>),
    Close,
}

struct OpenConnection(Arc<State>);

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.0.open_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

struct InFlight {
    state: Arc<State>,
    kind: Kind,
}

impl InFlight {
    fn new(state: &Arc<State>, kind: Kind) -> Self {
        let current = state.in_flight[kind as usize].fetch_add(1, Ordering::SeqCst) + 1;
        state.max_in_flight[kind as usize].fetch_max(current, Ordering::SeqCst);
        Self {
            state: Arc::clone(state),
            kind,
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.state.in_flight[self.kind as usize].fetch_sub(1, Ordering::SeqCst);
    }
}

async fn serve_connection<Stream>(stream: Stream, state: Arc<State>, connection: CancellationToken)
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    state.open_connections.fetch_add(1, Ordering::SeqCst);
    let _open = OpenConnection(Arc::clone(&state));
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (output, mut outputs) = mpsc::unbounded_channel::<Output>();

    let writer_task = {
        let connection = connection.clone();
        let packet_writer = PacketWriter::new(state.key.clone());
        async move {
            loop {
                let next = tokio::select! {
                    () = connection.cancelled() => break,
                    next = outputs.recv() => next,
                };
                match next {
                    Some(Output::Packet(packet)) => {
                        if !matches!(
                            packet_writer.write_packet(&mut writer, packet).await,
                            PacketWriteResult::Success
                        ) {
                            break;
                        }
                    }
                    Some(Output::Raw(bytes)) => {
                        if writer.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    Some(Output::Close) | None => break,
                }
            }
            connection.cancel();
        }
    };

    let reader_task = {
        let connection = connection.clone();
        async move {
            let packet_reader = PacketReader::new(state.key.clone());
            let logins = Logins::default();
            let mut single_connect = false;
            let mut first = true;
            loop {
                let read = tokio::select! {
                    () = connection.cancelled() => break,
                    read = packet_reader.read_packet(&mut reader) => read,
                };
                let PacketReadResult::Success(packet) = read else {
                    break;
                };
                if first {
                    first = false;
                    single_connect = state.mode == SingleConnect::Accept
                        && packet
                            .header()
                            .flags
                            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG);
                }
                let handler = respond(
                    Arc::clone(&state),
                    packet,
                    single_connect,
                    Arc::clone(&logins),
                    output.clone(),
                    connection.clone(),
                );
                if single_connect {
                    tokio::spawn(handler);
                    continue;
                }
                // A connection without single-connect carries one session.
                // A read during a reply detects a peer that gave up. The
                // session ends after its last reply unless the reply asks the
                // client for more data.
                tokio::pin!(handler);
                let mut probe = [0_u8; 1];
                tokio::select! {
                    biased;
                    continues = &mut handler => {
                        if continues {
                            continue;
                        }
                        let _sent = output.send(Output::Close);
                        return;
                    }
                    _ = reader.read(&mut probe) => {}
                }
                break;
            }
            // A closed read side ends the connection, like a real server.
            connection.cancel();
        }
    };

    tokio::join!(writer_task, reader_task);
}

/// User names of ASCII logins that wait for a `CONTINUE`, by session identifier.
type Logins = Arc<Mutex<HashMap<u32, String>>>;

/// Answers one request and returns true when the session expects another packet.
async fn respond(
    state: Arc<State>,
    request: Packet,
    single_connect: bool,
    logins: Logins,
    output: mpsc::UnboundedSender<Output>,
    connection: CancellationToken,
) -> bool {
    let kind = Kind::from_type(request.header().tacacs_type);
    let index = state.received.add(kind);
    let _in_flight = InFlight::new(&state, kind);
    let plan = Arc::clone(&state.plan.lock().unwrap());
    let continuation = kind == Kind::Authentication && request.header().seq_no > 1;
    let fault = plan(&Request {
        kind,
        index,
        continuation,
        user: request_user(&request, &logins),
    });
    if let Some(counter) = fault.counter() {
        state.injected[counter].add(kind);
    }
    let normal = reply(&request, single_connect, &logins, false);
    let continues = !matches!(fault, Fault::Error | Fault::Status(_))
        && AuthenticationReply::status_from_packet(&normal)
            == Some(TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass as u8)
        && kind == Kind::Authentication;
    let reply = |error: bool| {
        if error {
            reply(&request, single_connect, &logins, true)
        } else {
            normal.clone()
        }
    };
    match fault {
        Fault::None => {
            let _sent = output.send(Output::Packet(reply(false)));
        }
        Fault::Delay(delay) => {
            tokio::select! {
                () = connection.cancelled() => {}
                () = tokio::time::sleep(delay) => {
                    let _sent = output.send(Output::Packet(reply(false)));
                }
            }
        }
        Fault::Error => {
            let _sent = output.send(Output::Packet(reply(true)));
        }
        Fault::Close => {
            let _sent = output.send(Output::Close);
        }
        Fault::Hang => connection.cancelled().await,
        Fault::PartialHeader => {
            let bytes = wire(&state, reply(false));
            let _sent = output.send(Output::Raw(bytes[..6].to_vec()));
            connection.cancelled().await;
        }
        Fault::Status(status) => {
            let reply = reply(false);
            let offset = match kind {
                Kind::Authentication => AUTHENTICATION_REPLY_STATUS_OFFSET,
                Kind::Authorization => AUTHORIZATION_REPLY_STATUS_OFFSET,
                Kind::Accounting => ACCOUNTING_REPLY_STATUS_OFFSET,
            };
            let mut body = reply.body().to_vec();
            body[offset] = status;
            let packet = Packet::new(reply.header().clone(), body).unwrap();
            let _sent = output.send(Output::Packet(packet));
        }
        Fault::WrongSession | Fault::WrongSequence => {
            let reply = reply(false);
            let mut header = reply.header().clone();
            if fault == Fault::WrongSession {
                header.session_id = header.session_id.wrapping_add(0x1000_0000);
            } else {
                header.seq_no = header.seq_no.wrapping_add(2);
            }
            let packet = Packet::new(header, reply.body().to_vec()).unwrap();
            let _sent = output.send(Output::Packet(packet));
        }
        Fault::OversizedLength | Fault::BadHeader => {
            let mut bytes = wire(&state, reply(false));
            bytes.truncate(12);
            if fault == Fault::OversizedLength {
                bytes[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
            } else {
                bytes[0] = 0x00;
            }
            let _sent = output.send(Output::Raw(bytes));
            connection.cancelled().await;
        }
        Fault::BadKey => {
            let bytes = reply(false)
                .to_obfuscated(b"a-different-fixture-key")
                .to_bytes();
            let _sent = output.send(Output::Raw(bytes));
        }
    }
    continues
}

fn key() -> SecretBytes {
    SecretBytes::new(upstream_key().as_bytes().to_vec())
}

/// Encodes `packet` as the connection would send it.
fn wire(state: &State, packet: Packet) -> Vec<u8> {
    match &state.key {
        Some(key) => packet.to_obfuscated(key.expose_secret()).to_bytes(),
        None => packet.to_bytes(),
    }
}

fn request_user(request: &Packet, logins: &Logins) -> String {
    match request.header().tacacs_type {
        TacacsType::TacPlusAuthentication if request.header().seq_no > 1 => logins
            .lock()
            .unwrap()
            .get(&request.header().session_id)
            .cloned()
            .unwrap_or_default(),
        TacacsType::TacPlusAuthentication => AuthenticationStart::from_packet(request)
            .map(|start| start.user.clone())
            .unwrap_or_default(),
        TacacsType::TacPlusAuthorisation => AuthorizationRequest::from_packet(request)
            .map(|request| request.user.clone())
            .unwrap_or_default(),
        TacacsType::TacPlusAccounting => AccountingRequest::from_packet(request)
            .map(|request| request.user.clone())
            .unwrap_or_default(),
    }
}

fn reply(request: &Packet, single_connect: bool, logins: &Logins, error: bool) -> Packet {
    let body = match request.header().tacacs_type {
        TacacsType::TacPlusAuthentication => {
            authentication_reply(request, logins, error).to_bytes()
        }
        TacacsType::TacPlusAuthorisation => {
            let request = AuthorizationRequest::from_packet(request).unwrap();
            AuthorizationReply {
                status: if error {
                    TacacsAuthorizationStatus::TacPlusError
                } else {
                    TacacsAuthorizationStatus::TacPlusPassAdd
                },
                server_msg: request.user,
                data: String::new(),
                args: Vec::new(),
            }
            .to_bytes()
        }
        TacacsType::TacPlusAccounting => {
            let request = AccountingRequest::from_packet(request).unwrap();
            AccountingReply {
                status: if error {
                    TacacsAccountingStatus::TacPlusAcctStatusError
                } else {
                    TacacsAccountingStatus::TacPlusAcctStatusSuccess
                },
                server_msg: request.user,
                data: String::new(),
            }
            .to_bytes()
        }
    }
    .unwrap();
    let mut header = request.header().clone();
    header.seq_no += 1;
    header.length = u32::try_from(body.len()).unwrap();
    header.flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
    if single_connect {
        header.flags |= TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
    }
    Packet::new(header, body).unwrap()
}

/// Answers a PAP `START`, an ASCII `START`, or the `CONTINUE` of an ASCII login.
fn authentication_reply(request: &Packet, logins: &Logins, error: bool) -> AuthenticationReply {
    let session_id = request.header().session_id;
    let (user, password) = if request.header().seq_no == 1 {
        let start = AuthenticationStart::from_packet(request).unwrap();
        if start.authen_type == TacacsAuthenticationType::TacPlusAuthenTypeAscii && !error {
            logins
                .lock()
                .unwrap()
                .insert(session_id, start.user.clone());
            return AuthenticationReply {
                status: TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
                flags: TacacsAuthenticationReplyFlags::TAC_PLUS_REPLY_FLAG_NOECHO,
                server_msg: start.user.clone(),
                data: Vec::new(),
            };
        }
        (start.user.clone(), start.data.clone())
    } else {
        let next = AuthenticationContinue::from_packet(request).unwrap();
        let user = logins
            .lock()
            .unwrap()
            .get(&session_id)
            .cloned()
            .unwrap_or_default();
        (user, next.data.clone())
    };
    let status = if error {
        TacacsAuthenticationStatus::TacPlusAuthenStatusError
    } else if password == good_password() {
        TacacsAuthenticationStatus::TacPlusAuthenStatusPass
    } else {
        TacacsAuthenticationStatus::TacPlusAuthenStatusFail
    };
    AuthenticationReply {
        status,
        flags: TacacsAuthenticationReplyFlags::empty(),
        server_msg: user,
        data: Vec::new(),
    }
}
