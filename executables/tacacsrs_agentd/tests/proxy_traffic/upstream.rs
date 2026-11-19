//! Scripted plain-TCP TACACS+ upstream server with injectable faults.
//!
//! The server echoes the request user name in `server_msg` of every reply,
//! including error replies. A client can therefore detect a reply that the
//! proxy delivered to the wrong session. A replaceable fault plan selects the
//! behavior of each request from its operation and its per-operation index.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tacacsrs_networking::{PacketReadResult, PacketReader, PacketWriteResult, PacketWriter};
use tacacsrs_protocol::accounting::reply::AccountingReply;
use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::authentication::reply::AuthenticationReply;
use tacacsrs_protocol::authentication::start::AuthenticationStart;
use tacacsrs_protocol::authorization::reply::AuthorizationReply;
use tacacsrs_protocol::authorization::request::AuthorizationRequest;
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
    TacacsAuthorizationStatus, TacacsFlags, TacacsType,
};
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_secrets::SecretBytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Shared secret between the daemon and this upstream fixture.
pub(crate) const UPSTREAM_KEY: &str = "upstream-fixture-key";

/// Password that the fixture accepts for PAP authentication.
pub(crate) const GOOD_PASSWORD: &[u8] = b"fixture-password";

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
}

impl Fault {
    const fn counter(self) -> Option<usize> {
        match self {
            Self::None | Self::Delay(_) => None,
            Self::Error => Some(0),
            Self::Close => Some(1),
            Self::Hang => Some(2),
            Self::PartialHeader => Some(3),
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
    plan: Mutex<Plan>,
    received: PerKind,
    injected: [PerKind; 4],
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
        let address = listener.local_addr().unwrap();
        let state = Arc::new(State {
            mode,
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

    /// Returns the number of requests that received `fault`.
    pub(crate) fn injected(&self, fault: Fault) -> u64 {
        fault
            .counter()
            .map_or(0, |index| self.state.injected[index].total())
    }

    pub(crate) fn connections_accepted(&self) -> u64 {
        self.state.connections.load(Ordering::SeqCst)
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
}

async fn accept_loop(listener: TcpListener, state: Arc<State>, stop: CancellationToken) {
    loop {
        let accepted = tokio::select! {
            () = stop.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _peer)) = accepted else {
            continue;
        };
        state.connections.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(serve_connection(stream, Arc::clone(&state), stop.child_token()));
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

async fn serve_connection(
    stream: tokio::net::TcpStream,
    state: Arc<State>,
    connection: CancellationToken,
) {
    state.open_connections.fetch_add(1, Ordering::SeqCst);
    let _open = OpenConnection(Arc::clone(&state));
    let (mut reader, mut writer) = stream.into_split();
    let (output, mut outputs) = mpsc::unbounded_channel::<Output>();

    let writer_task = {
        let connection = connection.clone();
        async move {
            let packet_writer = PacketWriter::new(Some(key()));
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
            let packet_reader = PacketReader::new(Some(key()));
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
                    output.clone(),
                    connection.clone(),
                );
                if single_connect {
                    tokio::spawn(handler);
                    continue;
                }
                // A connection without single-connect carries one session.
                // A read during the session detects a peer that gave up.
                tokio::pin!(handler);
                let mut probe = [0_u8; 1];
                tokio::select! {
                    () = &mut handler => {
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

async fn respond(
    state: Arc<State>,
    request: Packet,
    single_connect: bool,
    output: mpsc::UnboundedSender<Output>,
    connection: CancellationToken,
) {
    let kind = Kind::from_type(request.header().tacacs_type);
    let index = state.received.add(kind);
    let _in_flight = InFlight::new(&state, kind);
    let plan = Arc::clone(&state.plan.lock().unwrap());
    let fault = plan(&Request { kind, index });
    if let Some(counter) = fault.counter() {
        state.injected[counter].add(kind);
    }
    let reply = |error: bool| reply(&request, single_connect, error);
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
            let bytes = reply(false)
                .to_obfuscated(UPSTREAM_KEY.as_bytes())
                .to_bytes();
            let _sent = output.send(Output::Raw(bytes[..6].to_vec()));
            connection.cancelled().await;
        }
    }
}

fn key() -> SecretBytes {
    SecretBytes::new(UPSTREAM_KEY.as_bytes().to_vec())
}

fn reply(request: &Packet, single_connect: bool, error: bool) -> Packet {
    let body = match request.header().tacacs_type {
        TacacsType::TacPlusAuthentication => {
            let start = AuthenticationStart::from_packet(request).unwrap();
            let status = if error {
                TacacsAuthenticationStatus::TacPlusAuthenStatusError
            } else if start.data == GOOD_PASSWORD {
                TacacsAuthenticationStatus::TacPlusAuthenStatusPass
            } else {
                TacacsAuthenticationStatus::TacPlusAuthenStatusFail
            };
            AuthenticationReply {
                status,
                flags: TacacsAuthenticationReplyFlags::empty(),
                server_msg: start.user.clone(),
                data: Vec::new(),
            }
            .to_bytes()
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
