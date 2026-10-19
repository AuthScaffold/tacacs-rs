//! Tests for the client facade, session selection, exchange, and preflight.

#[tokio::test]
async fn operational_counters_cover_shared_sessions_and_connection_outcomes() {
    use tokio::net::TcpListener;
    use crate::{PacketReader, PacketReadResult, PacketWriter, PacketWriteResult};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = PreparedEndpoint::new(
        listener.local_addr().unwrap().try_into().unwrap(),
        crate::PreparedTransport::Tcp,
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
            header.flags =
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
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
            .execute(&test_accounting_exchange(accounting_watchdog_preflight_request()))
            .await
            .unwrap();
    }
    peer.await.unwrap();
    if let Err(error) = client
        .close_and_join(crate::RequestDeadline::after(std::time::Duration::from_secs(1)).unwrap())
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

    let reserved_socket = tokio::net::TcpSocket::new_v4().unwrap();
    reserved_socket
        .bind("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let endpoint = PreparedEndpoint::new(
        reserved_socket.local_addr().unwrap().try_into().unwrap(),
        crate::PreparedTransport::Tcp,
        false,
        None,
        ConnectOptions::default().with_timeout(Duration::from_millis(100)),
    );
    let failed = endpoint.counters();
    let result =
        tokio::time::timeout(Duration::from_secs(2), crate::establish::establish_stream(&endpoint))
            .await
            .expect("the bounded TCP connection attempt must finish");
    let Err(error) = result else {
        panic!("the bound non-listening TCP socket must refuse the connection");
    };
    let native_refusal = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::ConnectionRefused)
    });
    let configured_timeout = error.chain().any(|cause| {
        cause
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    });
    assert!(native_refusal ^ configured_timeout, "unexpected connection error: {error:#}");
    let snapshot = failed.snapshot();
    assert_eq!(snapshot.connection_opens, 1);
    assert_eq!(snapshot.connection_successes, 0);
    assert_eq!(snapshot.connection_failures, 1);
    assert_eq!(
        snapshot.connection_timeouts,
        if configured_timeout {
            1
        } else {
            0
        }
    );
    assert_eq!(snapshot.connection_closes, 0);
    assert_eq!(snapshot.connection_aborts, 0);
    assert_eq!(snapshot.messages_sent, 0);
    assert_eq!(snapshot.messages_received, 0);
    assert_eq!(snapshot.errors_received, 0);
    assert_eq!(snapshot.sessions, 0);
    assert_eq!(snapshot.diagnostics.connecting, 0);
}

#[tokio::test]
async fn invalid_psk_fails_before_client_construction() {
    let result =
        crate::PskClientConfig::prepare("client", b"too-short", crate::PskHash::Sha256, &[], None);
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
use tacacsrs_protocol::authentication::reply::AuthenticationReply;
use tacacsrs_protocol::authorization::reply::AuthorizationReply;
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationReplyFlags,
    TacacsAuthenticationStatus, TacacsAuthorizationStatus, TacacsFlags, TacacsMajorVersion,
    TacacsMinorVersion, TacacsType,
};
use tacacsrs_protocol::exchange::{FixedExchange, PreparedBody};
use tacacsrs_protocol::exchange::accounting::AccountingExchange;
use tacacsrs_protocol::exchange::authentication::PapAuthenticationExchange;
use tacacsrs_protocol::failure::FailureCategory;
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_secrets::SecretBytes;

use super::TacacsClient;
use super::preflight::accounting_watchdog_preflight_request;
use crate::PreparedEndpoint;
use crate::codec::{PacketReadResult, PacketReader};
use crate::establish::{ConnectOptions, ConnectPreflight};
use crate::single_connect::SingleConnectionState;

fn test_accounting_exchange(request: AccountingRequest) -> AccountingExchange {
    AccountingExchange::new(request).unwrap()
}

struct TestAuthorizationExchange;

impl FixedExchange for TestAuthorizationExchange {
    type Reply = AuthorizationReply;

    fn packet_type(&self) -> TacacsType {
        TacacsType::TacPlusAuthorisation
    }

    fn minor_version(&self) -> TacacsMinorVersion {
        TacacsMinorVersion::TacacsPlusMinorVerDefault
    }

    fn request_body(&self) -> &PreparedBody {
        static BODY: std::sync::LazyLock<PreparedBody> = std::sync::LazyLock::new(|| {
            let operation = tacacsrs_protocol::operations::AuthorizationOperation::builder(
                "admin",
                15,
                tacacsrs_protocol::operations::AuthorizationAuthenticationContext::TacacsAscii,
            )
            .service("shell")
            .command("")
            .build()
            .unwrap();
            PreparedBody::encode(&operation.to_request().unwrap()).unwrap()
        });
        &BODY
    }

    fn decode_reply(&self, body: &[u8]) -> anyhow::Result<Self::Reply> {
        AuthorizationReply::from_bytes(body)
    }
}

fn server_template() -> PreparedEndpoint {
    PreparedEndpoint::new(
        crate::ServerAddress::parse("10.0.0.1:49", 49).unwrap(),
        crate::PreparedTransport::Tcp,
        true,
        None,
        ConnectOptions::default(),
    )
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

fn authentication_request(session_id: u32, sequence: u8) -> Packet {
    Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerOne,
            tacacs_type: TacacsType::TacPlusAuthentication,
            seq_no: sequence,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id,
            length: 0,
        },
        Vec::new(),
    )
    .unwrap()
}

fn authentication_reply(
    request: &Packet,
    status: TacacsAuthenticationStatus,
    flags: TacacsFlags,
) -> Packet {
    let body = AuthenticationReply {
        status,
        flags: TacacsAuthenticationReplyFlags::empty(),
        server_msg: String::new(),
        data: Vec::new(),
    }
    .to_bytes()
    .unwrap();
    let mut header = request.header().clone();
    header.seq_no = header.seq_no.wrapping_add(1);
    header.flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | flags;
    header.length = u32::try_from(body.len()).unwrap();
    Packet::new(header, body).unwrap()
}

async fn execute_with_response_diagnostics<Exchange>(
    exchange: Exchange,
    body: Vec<u8>,
    mutate_header: fn(&mut Header),
) -> (Result<Exchange::Reply, crate::FixedExchangeError>, crate::StatisticsSnapshot)
where
    Exchange: FixedExchange,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let PacketReadResult::Success(request) =
            PacketReader::new(None).read_packet(&mut stream).await
        else {
            panic!("request must decode");
        };
        let mut header = request.header().clone();
        header.seq_no = header.seq_no.wrapping_add(1);
        header.flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
        header.length = u32::try_from(body.len()).unwrap();
        mutate_header(&mut header);
        let response = Packet::new(header, body).unwrap();
        stream.write_all(&response.to_bytes()).await.unwrap();
    });

    let mut endpoint = server_template();
    endpoint.address = address.try_into().unwrap();
    endpoint.single_connection = false;
    let counters = endpoint.counters();
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), client.execute_classified(&exchange))
        .await
        .expect("the fixed exchange must finish");
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("the test server must finish")
        .unwrap();
    (result, counters.snapshot())
}

fn assert_malformed_exchange_diagnostics(snapshot: &crate::StatisticsSnapshot) {
    assert_eq!(snapshot.diagnostics.malformed_disconnects, 1);
    assert_eq!(snapshot.diagnostics.resets, 1);
    assert_eq!(snapshot.diagnostics.connected, 0);
    assert_eq!(snapshot.diagnostics.expected_replies, 0);
    assert_eq!(snapshot.sessions, 0);
    assert_eq!(
        snapshot.diagnostics.last_disconnect_reason,
        Some(crate::DisconnectReason::MalformedPacket)
    );
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
    spawn_single_stream_accounting_server_with_reply_flags(listener, vec![reply_flags; exchanges])
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
            let PacketReadResult::Success(packet) = reader.read_packet(&mut stream).await else {
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

async fn run_two_round_authentication_conversation(
    second_type: TacacsType,
) -> (anyhow::Result<Packet>, crate::StatisticsSnapshot, SingleConnectionState, bool) {
    tokio::time::timeout(Duration::from_secs(3), async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let reader = PacketReader::new(None);
            let PacketReadResult::Success(first) = reader.read_packet(&mut stream).await else {
                panic!("the first authentication request must decode");
            };
            let first_reply = authentication_reply(
                &first,
                TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
                TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
            );
            stream.write_all(&first_reply.to_bytes()).await.unwrap();

            let PacketReadResult::Success(second) = reader.read_packet(&mut stream).await else {
                panic!("the second authentication request must decode");
            };
            let mut second_reply = authentication_reply(
                &second,
                TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
                TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
            );
            if second_type != TacacsType::TacPlusAuthentication {
                let mut header = second_reply.header().clone();
                header.tacacs_type = second_type;
                second_reply = Packet::new(header, second_reply.body().to_vec()).unwrap();
            }
            stream.write_all(&second_reply.to_bytes()).await.unwrap();
        });

        let mut endpoint = server_template();
        endpoint.address = address.try_into().unwrap();
        let counters = endpoint.counters();
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let mut conversation = client.open_conversation().await.unwrap();
        let session_id = conversation.session_id().unwrap();
        conversation
            .round_trip(authentication_request(session_id, 1))
            .await
            .unwrap();
        let result = conversation
            .round_trip(authentication_request(session_id, 3))
            .await;
        if result.is_ok() {
            conversation.complete().await;
        }
        server_task.await.unwrap();
        let state = client.single_connection_state();
        let cached = client.shared_connection.current().await.is_some();
        (result, counters.snapshot(), state, cached)
    })
    .await
    .expect("the two-round native authentication conversation must finish")
}

#[tokio::test]
async fn connect_with_disabled_preflight_does_not_open_transport() {
    let mut server = server_template();
    server.address = crate::ServerAddress::parse("127.0.0.1:1", 49).unwrap();

    let client = TacacsClient::connect_prepared(server).await.unwrap();

    assert_eq!(client.single_connection_state(), SingleConnectionState::Initial);
}

#[tokio::test]
async fn invalid_fixed_request_never_opens_session() {
    let mut server = server_template();
    server.address = crate::ServerAddress::parse("127.0.0.1:1", 49).unwrap();
    server.options = ConnectOptions::default().with_preflight(ConnectPreflight::Disabled);
    let counters = server.counters();
    let client = TacacsClient::connect_prepared(server).await.unwrap();
    let mut request = accounting_watchdog_preflight_request();
    request.user = "x".repeat(256);

    let error = AccountingExchange::new(request).unwrap_err();

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.connection_opens, 0);
    assert_eq!(snapshot.messages_sent, 0);
    assert_eq!(snapshot.sessions, 0);
    assert!(format!("{error:#}").contains("exceeds 255 bytes"));
    client.close();
}

#[tokio::test]
async fn prepared_body_is_encoded_once_across_fresh_network_sessions() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountedCodec<'counter>(&'counter AtomicUsize);
    impl TacacsBodyTrait for CountedCodec<'_> {
        fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            accounting_watchdog_preflight_request().to_bytes()
        }
    }
    struct CountedExchange(PreparedBody);
    impl FixedExchange for CountedExchange {
        type Reply = AccountingReply;
        fn packet_type(&self) -> TacacsType {
            TacacsType::TacPlusAccounting
        }
        fn minor_version(&self) -> TacacsMinorVersion {
            TacacsMinorVersion::TacacsPlusMinorVerDefault
        }
        fn request_body(&self) -> &PreparedBody {
            &self.0
        }
        fn decode_reply(&self, body: &[u8]) -> anyhow::Result<AccountingReply> {
            AccountingReply::from_bytes(body)
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut endpoint = server_template();
    endpoint.address = listener.local_addr().unwrap().try_into().unwrap();
    endpoint.single_connection = false;
    let peer = tokio::spawn(async move {
        let mut packets = Vec::new();
        for status in [
            TacacsAccountingStatus::TacPlusAcctStatusError,
            TacacsAccountingStatus::TacPlusAcctStatusSuccess,
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let PacketReadResult::Success(packet) =
                PacketReader::new(None).read_packet(&mut stream).await
            else {
                panic!("the peer must receive a complete request");
            };
            let body = AccountingReply {
                status,
                server_msg: String::new(),
                data: String::new(),
            }
            .to_bytes()
            .unwrap();
            let mut header = packet.header().clone();
            header.seq_no = 2;
            header.length = u32::try_from(body.len()).unwrap();
            stream
                .write_all(&Packet::new(header, body).unwrap().to_bytes())
                .await
                .unwrap();
            packets.push(packet);
        }
        packets
    });
    let count = AtomicUsize::new(0);
    let exchange = CountedExchange(PreparedBody::encode(&CountedCodec(&count)).unwrap());
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    for status in [
        TacacsAccountingStatus::TacPlusAcctStatusError,
        TacacsAccountingStatus::TacPlusAcctStatusSuccess,
    ] {
        let reply = client.execute(&exchange).await.unwrap();
        assert_eq!(reply.status, status);
    }
    let packets = peer.await.unwrap();
    assert_ne!(packets[0].header().session_id, packets[1].header().session_id);
    for packet in packets {
        assert_eq!(packet.body(), exchange.request_body().as_bytes());
        assert_eq!(packet.header().length, exchange.request_body().wire_length());
        assert_eq!(packet.header().seq_no, 1);
    }
    assert_eq!(count.load(Ordering::Relaxed), 1);
    client.close();
}

#[test]
fn packet_obfuscation_key_uses_shared_secret_for_tls_servers() {
    let endpoint = PreparedEndpoint::new(
        crate::ServerAddress::parse("10.0.0.1:49", 49).unwrap(),
        crate::PreparedTransport::Tls(
            crate::TlsClientConfig::prepare(
                "10.0.0.1",
                None,
                crate::CertificateTrust::Platform,
                None,
                crate::CertificateVerification::Required,
            )
            .unwrap(),
        ),
        false,
        Some(tacacsrs_secrets::SecretBytes::new(b"legacy-secret".to_vec())),
        ConnectOptions::default(),
    );
    assert_eq!(endpoint.obfuscation_key.unwrap().expose_secret(), b"legacy-secret");
}

#[tokio::test]
async fn terminal_close_drains_dedicated_and_shared_conversations() {
    use tokio::io::AsyncReadExt;
    use crate::RequestDeadline;

    for shared in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TacacsClient::connect_prepared(PreparedEndpoint::new(
            listener.local_addr().unwrap().try_into().unwrap(),
            crate::PreparedTransport::Tcp,
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
                    &accounting_success_reply(&request, TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
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
    let client = TacacsClient::connect_prepared(PreparedEndpoint::new(
        listener.local_addr().unwrap().try_into().unwrap(),
        crate::PreparedTransport::Tcp,
        false,
        None,
        ConnectOptions::default(),
    ))
    .await
    .unwrap();
    let _conversation = client.open_conversation().await.unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let longer = client.close_and_join(RequestDeadline::after(Duration::from_secs(60)).unwrap());
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
    let endpoint = PreparedEndpoint::new(
        listener.local_addr().unwrap().try_into().unwrap(),
        crate::PreparedTransport::Tcp,
        false,
        None,
        ConnectOptions::default(),
    );
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let session = client.create_session().await.unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    session
        .send_packet(test_packet(session.session_id(), 1, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG))
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
        .execute_classified(&test_accounting_exchange(accounting_watchdog_preflight_request()))
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
    let endpoint = PreparedEndpoint::new(
        listener.local_addr().unwrap().try_into().unwrap(),
        crate::PreparedTransport::Tls(
            crate::TlsClientConfig::prepare(
                "localhost",
                None,
                CertificateTrust::Platform,
                None,
                crate::CertificateVerification::Required,
            )
            .unwrap(),
        ),
        false,
        None,
        ConnectOptions::default(),
    );
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let opening = client.open_conversation();
    tokio::pin!(opening);
    assert!(futures::poll!(&mut opening).is_pending());
    let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut hello = [0; 4096];
        assert!(peer.read(&mut hello).await.unwrap() > 0);
        ready_sender.send(()).unwrap();
        let mut remaining = Vec::new();
        peer.read_to_end(&mut remaining).await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(1), ready_receiver)
        .await
        .expect("the TLS peer must read ClientHello before terminal close")
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        client.close_and_join(RequestDeadline::after(Duration::from_secs(5)).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .expect("the stalled TLS peer must close")
        .unwrap();
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
    let client = TacacsClient::connect_prepared(PreparedEndpoint::new(
        address.try_into().unwrap(),
        crate::PreparedTransport::Tcp,
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
    assert!(cache.current().await.is_none());
    server_task.await.unwrap();
}

#[tokio::test]
async fn dropping_client_closes_retained_idle_dedicated_conversation() {
    use tokio::io::AsyncReadExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TacacsClient::connect_prepared(PreparedEndpoint::new(
        listener.local_addr().unwrap().try_into().unwrap(),
        crate::PreparedTransport::Tcp,
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
    let client = TacacsClient::connect_prepared(PreparedEndpoint::new(
        listener.local_addr().unwrap().try_into().unwrap(),
        crate::PreparedTransport::Tcp,
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
    use crate::connection::MultiplexedConnection;

    let client = TacacsClient::from_prepared(server_template());
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
    let session = connection.create_session().unwrap();
    let (transport, mut peer) = tokio::io::duplex(256);
    let (reader, writer) = tokio::io::split(transport);
    connection.run_with_halves(reader, writer);
    client
        .shared_connection
        .store_for_test(connection.clone())
        .await;
    let retirement =
        client.retire_shared_until(crate::RequestDeadline::after(Duration::from_secs(1)).unwrap());
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
    use crate::connection::MultiplexedConnection;

    let client = TacacsClient::from_prepared(server_template());
    for _cycle in 0..8 {
        let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
        let session = connection.create_session().unwrap();
        let (transport, mut peer) = tokio::io::duplex(256);
        let (reader, writer) = tokio::io::split(transport);
        connection.run_with_halves(reader, writer);
        client
            .shared_connection
            .store_for_test(connection.clone())
            .await;
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
        assert!(client.shared_connection.retiring_is_empty_for_test());
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
    endpoint.address = address.try_into().unwrap();
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let session = client.create_session().await.unwrap();
    run_session_exchange(&session).await;
    client
        .retire_shared_until(crate::RequestDeadline::after(Duration::from_secs(1)).unwrap())
        .await
        .unwrap();
    session.complete().await;
    assert!(client.shared_connection.current().await.is_none());
    server_task.await.unwrap();
}

#[tokio::test]
async fn dropping_client_retires_idle_cached_transport() {
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;

    use crate::connection::MultiplexedConnection;

    let client = TacacsClient::from_prepared(server_template());
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
    let (transport, mut peer) = tokio::io::duplex(256);
    let (reader, writer) = tokio::io::split(transport);
    connection.run_with_halves(reader, writer);
    client.shared_connection.store_for_test(connection).await;

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

    use crate::connection::MultiplexedConnection;

    let client = TacacsClient::from_prepared(server_template());
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
    let session = connection.create_session().unwrap();
    let (transport, mut peer) = tokio::io::duplex(256);
    let (reader, writer) = tokio::io::split(transport);
    connection.run_with_halves(reader, writer);
    client
        .shared_connection
        .store_for_test(Arc::clone(&connection))
        .await;
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
    server.address = listener_address.try_into().unwrap();
    server.single_connection = false;
    let client = TacacsClient::connect_prepared(server).await.unwrap();

    let reply = client
        .execute(&test_accounting_exchange(accounting_watchdog_preflight_request()))
        .await
        .unwrap();
    assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);

    let request = receive_request(&mut request_receiver).await;
    assert_eq!(request.header().seq_no, 1);
    assert_eq!(request.header().tacacs_type, TacacsType::TacPlusAccounting);
    server_task.await.unwrap();
}

#[tokio::test]
async fn dedicated_fixed_exchange_marks_valid_wrong_type_and_minor_as_protocol() {
    let body = AccountingReply {
        status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
        server_msg: String::new(),
        data: String::new(),
    }
    .to_bytes()
    .unwrap();
    for mutate in [
        (|header: &mut Header| header.tacacs_type = TacacsType::TacPlusAuthorisation)
            as fn(&mut Header),
        |header| header.minor_version = TacacsMinorVersion::TacacsPlusMinorVerOne,
    ] {
        let (result, snapshot) = execute_with_response_diagnostics(
            test_accounting_exchange(accounting_watchdog_preflight_request()),
            body.clone(),
            mutate,
        )
        .await;
        let Err(error) = result else {
            panic!("the invalid response header must fail");
        };
        assert_eq!(error.transmission_state(), crate::TransmissionState::OutcomeUnknown);
        assert_eq!(error.known_category(), Some(FailureCategory::Protocol));
        assert_malformed_exchange_diagnostics(&snapshot);
    }
}

#[tokio::test]
async fn malformed_fixed_reply_bodies_and_pap_getpass_are_protocol_failures() {
    let malformed_accounting = execute_with_response_diagnostics(
        test_accounting_exchange(accounting_watchdog_preflight_request()),
        vec![0],
        |_| {},
    )
    .await;
    let malformed_authorization =
        execute_with_response_diagnostics(TestAuthorizationExchange, vec![0], |_| {}).await;
    let malformed_authentication = execute_with_response_diagnostics(
        PapAuthenticationExchange::new(
            "admin",
            SecretBytes::new(b"password".to_vec()),
            "tty0",
            "192.0.2.1",
            15,
        )
        .unwrap(),
        vec![0],
        |_| {},
    )
    .await;
    let getpass = AuthenticationReply {
        status: TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
        flags: TacacsAuthenticationReplyFlags::empty(),
        server_msg: "Password:".to_owned(),
        data: Vec::new(),
    }
    .to_bytes()
    .unwrap();
    let nonterminal_pap = execute_with_response_diagnostics(
        PapAuthenticationExchange::new(
            "admin",
            SecretBytes::new(b"password".to_vec()),
            "tty0",
            "192.0.2.1",
            15,
        )
        .unwrap(),
        getpass,
        |_| {},
    )
    .await;

    for (result, snapshot) in [
        (malformed_accounting.0.map(|_| ()), malformed_accounting.1),
        (malformed_authorization.0.map(|_| ()), malformed_authorization.1),
        (malformed_authentication.0.map(|_| ()), malformed_authentication.1),
        (nonterminal_pap.0.map(|_| ()), nonterminal_pap.1),
    ] {
        let error = result.unwrap_err();
        assert_eq!(error.transmission_state(), crate::TransmissionState::OutcomeUnknown);
        assert_eq!(error.known_category(), Some(FailureCategory::Protocol));
        assert_malformed_exchange_diagnostics(&snapshot);
    }
}

#[tokio::test]
async fn early_dedicated_header_rejections_count_one_malformed_disconnect() {
    for mutate in [
        (|header: &mut Header| header.session_id = header.session_id.wrapping_add(1))
            as fn(&mut Header),
        |header| header.seq_no = header.seq_no.wrapping_add(2),
    ] {
        let body = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: String::new(),
            data: String::new(),
        }
        .to_bytes()
        .unwrap();
        let (result, snapshot) = execute_with_response_diagnostics(
            test_accounting_exchange(accounting_watchdog_preflight_request()),
            body,
            mutate,
        )
        .await;
        let error = result.unwrap_err();
        assert_eq!(error.transmission_state(), crate::TransmissionState::OutcomeUnknown);
        assert_eq!(error.known_category(), Some(FailureCategory::Protocol));
        assert_malformed_exchange_diagnostics(&snapshot);
    }
}

#[tokio::test]
async fn dedicated_parser_rejection_counts_one_malformed_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let PacketReadResult::Success(_) = PacketReader::new(None).read_packet(&mut stream).await
        else {
            panic!("the request must decode");
        };
        stream.write_all(&[0; 12]).await.unwrap();
    });
    let mut endpoint = server_template();
    endpoint.address = address.try_into().unwrap();
    endpoint.single_connection = false;
    let counters = endpoint.counters();
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let error = client
        .execute_classified(&test_accounting_exchange(accounting_watchdog_preflight_request()))
        .await
        .unwrap_err();
    assert_eq!(error.transmission_state(), crate::TransmissionState::OutcomeUnknown);
    assert_eq!(error.known_category(), Some(FailureCategory::Protocol));
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
    assert_malformed_exchange_diagnostics(&counters.snapshot());
}

#[tokio::test]
async fn invalid_single_connect_first_reply_is_not_promoted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let PacketReadResult::Success(request) =
            PacketReader::new(None).read_packet(&mut stream).await
        else {
            panic!("the request must decode");
        };
        let mut reply =
            accounting_success_reply(&request, TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG);
        let mut header = reply.header().clone();
        header.tacacs_type = TacacsType::TacPlusAuthorisation;
        reply = Packet::new(header, reply.body().to_vec()).unwrap();
        stream.write_all(&reply.to_bytes()).await.unwrap();
    });
    let mut endpoint = server_template();
    endpoint.address = address.try_into().unwrap();
    let counters = endpoint.counters();
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        client
            .execute_classified(&test_accounting_exchange(accounting_watchdog_preflight_request())),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.known_category(), Some(FailureCategory::Protocol));
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
    assert!(client.shared_connection.current().await.is_none());
    assert_eq!(client.single_connection_state(), SingleConnectionState::Initial);
    assert_malformed_exchange_diagnostics(&counters.snapshot());
}

#[tokio::test]
async fn late_dedicated_conversation_header_rejection_cancels_promotion() {
    let (result, snapshot, state, cached) =
        run_two_round_authentication_conversation(TacacsType::TacPlusAccounting).await;
    assert!(result.is_err());
    assert_eq!(state, SingleConnectionState::Initial);
    assert!(!cached);
    assert_malformed_exchange_diagnostics(&snapshot);
}

#[tokio::test]
async fn valid_interactive_conversation_promotes_after_terminal_reply() {
    let (result, snapshot, state, cached) =
        run_two_round_authentication_conversation(TacacsType::TacPlusAuthentication).await;
    assert_eq!(
        AuthenticationReply::from_packet(&result.unwrap())
            .unwrap()
            .status,
        TacacsAuthenticationStatus::TacPlusAuthenStatusPass
    );
    assert_eq!(state, SingleConnectionState::Supported);
    assert!(cached);
    assert_eq!(snapshot.diagnostics.malformed_disconnects, 0);
    assert_eq!(snapshot.sessions, 1);
}

#[tokio::test]
async fn local_conversation_request_rejection_sends_no_packet_and_is_not_malformed() {
    use tokio::io::AsyncReadExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.read(&mut byte))
                .await
                .is_err(),
            "local request rejection must not send bytes"
        );
    });
    let mut endpoint = server_template();
    endpoint.address = address.try_into().unwrap();
    endpoint.single_connection = false;
    let counters = endpoint.counters();
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let mut conversation = tokio::time::timeout(Duration::from_secs(1), client.open_conversation())
        .await
        .expect("the local-validation conversation setup must finish")
        .unwrap();
    let wrong_session = conversation.session_id().unwrap().wrapping_add(1);
    assert!(tokio::time::timeout(
        Duration::from_secs(1),
        conversation.round_trip(authentication_request(wrong_session, 1)),
    )
    .await
    .expect("the local request rejection must finish")
    .is_err());
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.messages_sent, 0);
    assert_eq!(snapshot.diagnostics.malformed_disconnects, 0);
    assert_eq!(snapshot.sessions, 0);
}

#[tokio::test]
async fn shared_body_decoder_failure_does_not_abort_another_live_session() {
    use tokio::io::AsyncReadExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let reader = PacketReader::new(None);
        let PacketReadResult::Success(probe) = reader.read_packet(&mut stream).await else {
            panic!("the probe request must decode");
        };
        stream
            .write_all(
                &accounting_success_reply(&probe, TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
                    .to_bytes(),
            )
            .await
            .unwrap();
        let PacketReadResult::Success(first) = reader.read_packet(&mut stream).await else {
            panic!("the first shared request must decode");
        };
        let PacketReadResult::Success(second) = reader.read_packet(&mut stream).await else {
            panic!("the second shared request must decode");
        };
        let mut malformed_header = first.header().clone();
        malformed_header.seq_no = malformed_header.seq_no.wrapping_add(1);
        malformed_header.flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
        malformed_header.length = 1;
        stream
            .write_all(&Packet::new(malformed_header, vec![0]).unwrap().to_bytes())
            .await
            .unwrap();
        stream
            .write_all(&accounting_success_reply(&second, TacacsFlags::empty()).to_bytes())
            .await
            .unwrap();
        let _ = release_receiver.await;
        let mut remaining = Vec::new();
        let _ = stream.read_to_end(&mut remaining).await;
    });
    let mut endpoint = server_template();
    endpoint.address = address.try_into().unwrap();
    let counters = endpoint.counters();
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        client.execute(&test_accounting_exchange(accounting_watchdog_preflight_request())),
    )
    .await
    .expect("the shared-connection probe must finish")
    .unwrap();
    let prepared = test_accounting_exchange(accounting_watchdog_preflight_request());
    let first = client.execute_classified(&prepared);
    let second = client.execute_classified(&prepared);
    let (first, second) =
        tokio::time::timeout(Duration::from_secs(1), async { tokio::join!(first, second) })
            .await
            .unwrap();
    let results = [first.map(|_| ()), second.map(|_| ())];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let error = results.into_iter().find_map(Result::err).unwrap();
    assert_eq!(error.known_category(), Some(FailureCategory::Protocol));
    assert!(client.shared_connection.current().await.is_some());
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.diagnostics.malformed_disconnects, 0);
    assert_eq!(snapshot.sessions, 2);
    let _ = release_sender.send(());
    client
        .close_and_join(crate::RequestDeadline::after(Duration::from_secs(1)).unwrap())
        .await
        .unwrap_or_else(|error| {
            assert!(
                error.chain().any(|cause| cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)),
                "unexpected shutdown error: {error:#}"
            );
        });
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn valid_terminal_denial_and_server_error_remain_successful_replies() {
    for status in [
        TacacsAuthenticationStatus::TacPlusAuthenStatusFail,
        TacacsAuthenticationStatus::TacPlusAuthenStatusError,
    ] {
        let body = AuthenticationReply {
            status,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: String::new(),
            data: Vec::new(),
        }
        .to_bytes()
        .unwrap();
        let (reply, snapshot) = execute_with_response_diagnostics(
            PapAuthenticationExchange::new(
                "admin",
                SecretBytes::new(b"password".to_vec()),
                "tty0",
                "192.0.2.1",
                15,
            )
            .unwrap(),
            body,
            |_| {},
        )
        .await;
        let reply = reply.unwrap();
        assert_eq!(reply.status, status);
        assert_eq!(snapshot.diagnostics.malformed_disconnects, 0);
        assert_eq!(snapshot.sessions, 1);
    }

    let authorization = AuthorizationReply {
        status: TacacsAuthorizationStatus::TacPlusError,
        server_msg: String::new(),
        data: String::new(),
        args: Vec::new(),
    }
    .to_bytes()
    .unwrap();
    let (reply, snapshot) =
        execute_with_response_diagnostics(TestAuthorizationExchange, authorization, |_| {}).await;
    assert_eq!(reply.unwrap().status, TacacsAuthorizationStatus::TacPlusError);
    assert_eq!(snapshot.diagnostics.malformed_disconnects, 0);
    assert_eq!(snapshot.sessions, 1);
}

#[tokio::test]
async fn header_and_body_eof_remain_uncategorized_transport_failures() {
    for body_eof in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let PacketReadResult::Success(request) =
                PacketReader::new(None).read_packet(&mut stream).await
            else {
                panic!("request must decode");
            };
            if body_eof {
                let mut header = request.header().clone();
                header.seq_no = 2;
                header.length = 1;
                stream.write_all(&header.to_bytes()).await.unwrap();
            } else {
                stream.write_all(&[0xc0]).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        });
        let mut endpoint = server_template();
        endpoint.address = address.try_into().unwrap();
        endpoint.single_connection = false;
        let counters = endpoint.counters();
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let result = client
            .execute_classified(&test_accounting_exchange(accounting_watchdog_preflight_request()))
            .await;
        let Err(error) = result else {
            panic!("the truncated response must fail");
        };
        assert_eq!(error.known_category(), None);
        assert_eq!(error.transmission_state(), crate::TransmissionState::OutcomeUnknown);
        client
            .close_and_join(crate::RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap();
        let diagnostics = counters.snapshot().diagnostics;
        assert_eq!(diagnostics.read_errors, 1);
        assert_eq!(diagnostics.resets, 1);
        assert_eq!(diagnostics.peer_disconnects, 1);
        assert_eq!(diagnostics.malformed_disconnects, 0);
    }
}

#[tokio::test]
async fn expired_exchange_does_not_open_a_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut endpoint = server_template();
    endpoint.address = listener.local_addr().unwrap().try_into().unwrap();
    endpoint.single_connection = false;
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let error = client
        .execute_classified_until(
            &test_accounting_exchange(accounting_watchdog_preflight_request()),
            crate::RequestDeadline::after(Duration::ZERO).unwrap(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.transmission_state(), crate::TransmissionState::NotSent);
    assert_eq!(error.known_category(), None);
    let accept = listener.accept();
    tokio::pin!(accept);
    assert!(futures::poll!(&mut accept).is_pending());
}

#[tokio::test]
async fn deadline_classifies_stalled_tls_and_sent_requests() {
    use tokio::io::AsyncReadExt;
    use crate::{CertificateTrust, PacketReader, PacketReadResult, RequestDeadline, TransmissionState};

    for tls in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = if tls {
            crate::PreparedTransport::Tls(
                crate::TlsClientConfig::prepare(
                    "localhost",
                    None,
                    CertificateTrust::Platform,
                    None,
                    crate::CertificateVerification::Required,
                )
                .unwrap(),
            )
        } else {
            crate::PreparedTransport::Tcp
        };
        let endpoint = PreparedEndpoint::new(
            listener.local_addr().unwrap().try_into().unwrap(),
            transport,
            false,
            None,
            ConnectOptions::default(),
        );
        let counters = endpoint.counters();
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let deadline = RequestDeadline::after(Duration::from_millis(200)).unwrap();
        let prepared = test_accounting_exchange(accounting_watchdog_preflight_request());
        let exchange = client.execute_classified_until(&prepared, deadline);
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
        let (result, ()) =
            tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(exchange, peer) })
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
        client
            .close_and_join(RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.diagnostics.connecting, 0);
        assert_eq!(snapshot.diagnostics.expected_replies, 0);
        assert_eq!(snapshot.diagnostics.malformed_disconnects, 0);
        if tls {
            assert_eq!(snapshot.connection_failures, 1);
            assert_eq!(snapshot.connection_timeouts, 1);
            assert_eq!(snapshot.diagnostics.handshake_failures, 1);
        }
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
    server.address = listener_address.try_into().unwrap();
    server.options = ConnectOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog);
    let client = TacacsClient::connect_prepared(server).await.unwrap();

    let preflight_packet = receive_request(&mut request_receiver).await;
    let diagnostics = client.endpoint.counters().snapshot().diagnostics;
    assert_eq!(diagnostics.watchdog_preflights, 1);
    assert_eq!(diagnostics.watchdog_successes, 1);
    assert_eq!(diagnostics.watchdog_failures, 0);
    let preflight_request = AccountingRequest::from_packet(&preflight_packet).unwrap();
    assert!(preflight_request
        .flags
        .contains(TacacsAccountingFlags::WATCHDOG));
    assert!(preflight_packet
        .header()
        .flags
        .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
    assert_eq!(client.single_connection_state(), SingleConnectionState::Supported);
    assert!(client.shared_connection.current().await.is_some());

    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        client.execute(&test_accounting_exchange(accounting_watchdog_preflight_request())),
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
    server.address = listener_address.try_into().unwrap();
    server.options = ConnectOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog);
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
    assert_eq!(client.single_connection_state(), SingleConnectionState::NotSupported);
    assert!(client.shared_connection.current().await.is_none());

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
    server.address = listener_address.try_into().unwrap();
    let client = TacacsClient::from_prepared(server);

    for _ in 0..3 {
        let reply = tokio::time::timeout(
            Duration::from_secs(1),
            client.execute(&test_accounting_exchange(accounting_watchdog_preflight_request())),
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
    assert_eq!(client.single_connection_state(), SingleConnectionState::Supported);

    server_task.await.unwrap();
}

#[tokio::test]
async fn unsupported_single_connect_probe_makes_later_sessions_dedicated_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_address = listener.local_addr().unwrap();
    let (mut request_receiver, server_task) =
        spawn_accounting_server(listener, 2, TacacsFlags::empty());

    let mut server = server_template();
    server.address = listener_address.try_into().unwrap();
    let client = TacacsClient::from_prepared(server);

    let first_session = client.create_session().await.unwrap();
    run_session_exchange(&first_session).await;
    first_session.complete().await;
    let first_request = receive_request(&mut request_receiver).await;
    assert!(first_request
        .header()
        .flags
        .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));

    assert_eq!(client.single_connection_state(), SingleConnectionState::NotSupported);

    let second_session = client.create_session().await.unwrap();
    run_session_exchange(&second_session).await;
    second_session.complete().await;
    let second_request = receive_request(&mut request_receiver).await;
    assert!(!second_request
        .header()
        .flags
        .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));

    server_task.await.unwrap();
    assert_eq!(client.single_connection_state(), SingleConnectionState::NotSupported);
}

#[tokio::test]
async fn timed_out_probe_recovers_and_promotes_on_the_same_client() {
    use tokio::io::AsyncReadExt;
    use crate::{PacketReader, PacketReadResult, RequestDeadline, TransmissionState};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut endpoint = server_template();
    endpoint.address = listener.local_addr().unwrap().try_into().unwrap();
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let prepared = test_accounting_exchange(accounting_watchdog_preflight_request());
    let request = client.execute_classified_until(
        &prepared,
        RequestDeadline::after(Duration::from_millis(100)).unwrap(),
    );
    let peer = async {
        let (mut peer, _) = listener.accept().await.unwrap();
        assert!(matches!(
            PacketReader::new(None).read_packet(&mut peer).await,
            PacketReadResult::Success(_)
        ));
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    };
    let (result, ()) =
        tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(request, peer) })
            .await
            .unwrap();
    assert_eq!(result.unwrap_err().transmission_state(), TransmissionState::OutcomeUnknown);
    assert_eq!(client.single_connection_state(), SingleConnectionState::Initial);
    let (mut requests, server_task) = spawn_single_stream_accounting_server(
        listener,
        2,
        TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
    );
    for _ in 0..2 {
        tokio::time::timeout(
            Duration::from_secs(1),
            client.execute(&test_accounting_exchange(accounting_watchdog_preflight_request())),
        )
        .await
        .unwrap()
        .unwrap();
    }
    assert!(receive_request(&mut requests)
        .await
        .header()
        .flags
        .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
    assert!(!receive_request(&mut requests)
        .await
        .header()
        .flags
        .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
    assert_eq!(client.single_connection_state(), SingleConnectionState::Supported);
    server_task.await.unwrap();
}

#[tokio::test]
async fn stale_negotiation_attempt_uses_dedicated_stream_after_not_supported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_address = listener.local_addr().unwrap();
    let (mut request_receiver, server_task) =
        spawn_accounting_server(listener, 1, TacacsFlags::empty());

    let mut server = server_template();
    server.address = listener_address.try_into().unwrap();
    let client = TacacsClient::from_prepared(server);

    client.update_single_connection_state(SingleConnectionState::NotSupported);

    let session = client
        .create_single_connect_negotiation_session(None)
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
    server.address = listener_address.try_into().unwrap();
    let client = TacacsClient::from_prepared(server);

    let first_session = client.create_session().await.unwrap();
    assert_eq!(client.single_connection_state(), SingleConnectionState::Negotiating);

    let second_session = client.create_session().await.unwrap();
    run_session_exchange(&second_session).await;
    second_session.complete().await;
    let second_request = receive_request(&mut request_receiver).await;

    assert!(!second_request
        .header()
        .flags
        .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
    assert_eq!(client.single_connection_state(), SingleConnectionState::Negotiating);

    run_session_exchange(&first_session).await;
    first_session.complete().await;
    let first_request = receive_request(&mut request_receiver).await;
    assert!(first_request
        .header()
        .flags
        .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
    server_task.await.unwrap();
}
