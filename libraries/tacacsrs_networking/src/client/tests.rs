//! Tests for the client facade, session selection, exchange, and preflight.

#[tokio::test]
async fn operational_counters_cover_shared_sessions_and_connection_outcomes() {
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
            .execute(AccountingWatchdogExchange(accounting_watchdog_preflight_request()))
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
    let result =
        crate::PreparedEndpoint::tcp("127.0.0.1:1", false, None, crate::ConnectOptions::default())
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

use super::TacacsClient;
use super::preflight::{AccountingWatchdogExchange, accounting_watchdog_preflight_request};
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

#[tokio::test]
async fn connect_with_disabled_preflight_does_not_open_transport() {
    let mut server = server_template();
    server.address = "127.0.0.1:1".to_owned();

    let client = TacacsClient::connect_prepared(server).await.unwrap();

    assert_eq!(client.single_connection_state(), SingleConnectionState::Initial);
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
    assert!(cache.current().await.is_none());
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
    endpoint.address = address.to_string();
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
    use crate::{CertificateTrust, PacketReader, PacketReadResult, RequestDeadline, TransmissionState};

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
        let counters = endpoint.counters();
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
    server.address = listener_address.to_string();
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
    endpoint.address = listener.local_addr().unwrap().to_string();
    let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
    let request = client.execute_classified_until(
        TestAccountingExchange(accounting_watchdog_preflight_request()),
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
            client.execute(TestAccountingExchange(accounting_watchdog_preflight_request())),
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
    server.address = listener_address.to_string();
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
    server.address = listener_address.to_string();
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
