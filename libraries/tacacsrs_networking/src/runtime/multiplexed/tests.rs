use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use super::MultiplexedConnection;
use crate::session::{ClientConversation, ExpectedResponseHeader, PacketDispatchError};

fn conversation_packet(session_id: u32, seq_no: u8) -> Packet {
    Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAuthorisation,
            seq_no,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id,
            length: 0,
        },
        Vec::new(),
    )
    .unwrap()
}

fn request(session_id: u32) -> Packet {
    conversation_packet(session_id, 1)
}

fn reply(session_id: u32) -> Packet {
    Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAuthorisation,
            seq_no: 2,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG
                | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
            session_id,
            length: 0,
        },
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn test_connection_creation() {
    let _conn = MultiplexedConnection::new(Some(b"test_key"));
}

#[test]
fn test_connection_without_obfuscation() {
    let _conn = MultiplexedConnection::new(None);
}

#[tokio::test]
async fn routes_out_of_order_replies_by_session_id() {
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let first = connection.create_session().await.unwrap();
    let second = connection.create_session().await.unwrap();

    connection
        .session_manager
        .send_message_to_session(reply(second.session_id()))
        .await
        .unwrap();
    connection
        .session_manager
        .send_message_to_session(reply(first.session_id()))
        .await
        .unwrap();

    let first_reply = first.receive_packet().await.unwrap();
    let second_reply = second.receive_packet().await.unwrap();
    assert_eq!(first_reply.header().session_id, first.session_id());
    assert_eq!(second_reply.header().session_id, second.session_id());

    first.complete().await;
    second.complete().await;
}

#[tokio::test]
async fn completed_session_rejects_late_reply() {
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let session = connection.create_session().await.unwrap();
    let session_id = session.session_id();

    session.complete().await;

    let result = connection
        .session_manager
        .send_message_to_session(reply(session_id))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn routes_out_of_order_fixed_replies_by_session_id() {
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let first = connection.create_session().await.unwrap();
    let second = connection.create_session().await.unwrap();
    let first_receiver = connection
        .session_manager
        .prepare_fixed_response(
            first.session_id(),
            ExpectedResponseHeader::for_request(&request(first.session_id())),
        )
        .await
        .unwrap();
    let second_receiver = connection
        .session_manager
        .prepare_fixed_response(
            second.session_id(),
            ExpectedResponseHeader::for_request(&request(second.session_id())),
        )
        .await
        .unwrap();

    connection
        .session_manager
        .send_message_to_session(reply(second.session_id()))
        .await
        .unwrap();
    connection
        .session_manager
        .send_message_to_session(reply(first.session_id()))
        .await
        .unwrap();

    let first_reply = first_receiver.await.unwrap().unwrap();
    let second_reply = second_receiver.await.unwrap().unwrap();
    assert_eq!(first_reply.header().session_id, first.session_id());
    assert_eq!(second_reply.header().session_id, second.session_id());

    first.complete().await;
    second.complete().await;
}

#[tokio::test]
async fn rejects_invalid_fixed_response_metadata() {
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let session = connection.create_session().await.unwrap();
    let receiver = connection
        .session_manager
        .prepare_fixed_response(
            session.session_id(),
            ExpectedResponseHeader::for_request(&request(session.session_id())),
        )
        .await
        .unwrap();
    let invalid_reply = request(session.session_id());

    let dispatch = connection
        .session_manager
        .send_message_to_session(invalid_reply)
        .await;
    assert!(matches!(dispatch, Err(PacketDispatchError::ProtocolViolation { .. })));
    assert!(receiver.await.unwrap().is_err());

    session.complete().await;
}

#[tokio::test]
async fn later_unset_flag_does_not_close_confirmed_connection() {
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let session = connection.create_session().await.unwrap();
    let receiver = connection
        .session_manager
        .prepare_fixed_response(
            session.session_id(),
            ExpectedResponseHeader::for_request(&request(session.session_id())),
        )
        .await
        .unwrap();

    connection
        .session_manager
        .set_single_connection_state(false)
        .await;
    connection
        .session_manager
        .send_message_to_session(reply(session.session_id()))
        .await
        .unwrap();
    receiver.await.unwrap().unwrap();

    let close = connection.session_manager.wait_for_close();
    tokio::pin!(close);
    assert!(tokio::time::timeout(Duration::from_millis(25), &mut close)
        .await
        .is_err());

    session.complete().await;
    assert!(tokio::time::timeout(Duration::from_millis(25), &mut close)
        .await
        .is_err());
}

#[tokio::test]
async fn conversation_enforces_multi_round_sequence_progression() {
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let session = connection.create_session().await.unwrap();
    let session_id = session.session_id();
    let mut conversation = ClientConversation::new(crate::session::ClientSession::shared(session));

    let conversation_task = tokio::spawn(async move {
        assert_eq!(conversation.session_id(), Some(session_id));
        let first = conversation
            .round_trip(conversation_packet(session_id, 1))
            .await
            .unwrap();
        let second = conversation
            .round_trip(conversation_packet(session_id, 3))
            .await
            .unwrap();
        conversation.complete().await;
        assert_eq!(conversation.session_id(), None);
        (first, second)
    });

    tokio::task::yield_now().await;
    connection
        .session_manager
        .send_message_to_session(conversation_packet(session_id, 2))
        .await
        .unwrap();
    tokio::task::yield_now().await;
    connection
        .session_manager
        .send_message_to_session(conversation_packet(session_id, 4))
        .await
        .unwrap();

    let (first, second) = conversation_task.await.unwrap();
    assert_eq!(first.header().seq_no, 2);
    assert_eq!(second.header().seq_no, 4);
    assert!(matches!(
        connection
            .session_manager
            .send_message_to_session(conversation_packet(session_id, 6))
            .await,
        Err(PacketDispatchError::UnknownSession(id)) if id == session_id
    ));
}

#[tokio::test]
async fn invalid_conversation_reply_completes_session() {
    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let session = connection.create_session().await.unwrap();
    let session_id = session.session_id();
    let mut conversation = ClientConversation::new(crate::session::ClientSession::shared(session));

    let conversation_task = tokio::spawn(async move {
        conversation
            .round_trip(conversation_packet(session_id, 1))
            .await
    });
    tokio::task::yield_now().await;
    connection
        .session_manager
        .send_message_to_session(conversation_packet(session_id, 4))
        .await
        .unwrap();

    assert!(conversation_task.await.unwrap().is_err());
    tokio::task::yield_now().await;
    assert!(matches!(
        connection
            .session_manager
            .send_message_to_session(conversation_packet(session_id, 2))
            .await,
        Err(PacketDispatchError::UnknownSession(id)) if id == session_id
    ));
}

#[tokio::test]
#[ignore = "manual multiplexed routing baseline"]
async fn shared_session_routing_burst_baseline() {
    const EXCHANGE_COUNT: u32 = 512;

    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let started = Instant::now();
    let mut sessions = Vec::with_capacity(usize::try_from(EXCHANGE_COUNT).unwrap());

    for _ in 0..EXCHANGE_COUNT {
        sessions.push(connection.create_session().await.unwrap());
    }
    for session in sessions.iter().rev() {
        connection
            .session_manager
            .send_message_to_session(reply(session.session_id()))
            .await
            .unwrap();
    }
    for session in sessions {
        session.receive_packet().await.unwrap();
        session.complete().await;
    }

    let elapsed = started.elapsed();
    eprintln!(
        "shared routing baseline: {EXCHANGE_COUNT} exchanges in {elapsed:?} ({:.0} exchanges/s)",
        f64::from(EXCHANGE_COUNT) / elapsed.as_secs_f64(),
    );
}

#[tokio::test]
#[ignore = "manual direct fixed routing baseline"]
async fn direct_fixed_routing_burst_baseline() {
    const EXCHANGE_COUNT: u32 = 512;

    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let mut outbound = connection.session_manager.take_receiver().await.unwrap();
    let drain_task = tokio::spawn(async move { while outbound.recv().await.is_some() {} });
    let started = Instant::now();
    let mut sessions = Vec::with_capacity(usize::try_from(EXCHANGE_COUNT).unwrap());

    for _ in 0..EXCHANGE_COUNT {
        sessions.push(
            connection
                .create_fixed_session(ExpectedResponseHeader::fixed(
                    TacacsType::TacPlusAuthorisation,
                    TacacsMinorVersion::TacacsPlusMinorVerDefault,
                ))
                .await
                .unwrap(),
        );
    }
    for session in sessions.iter().rev() {
        connection
            .session_manager
            .send_message_to_session(reply(session.session_id()))
            .await
            .unwrap();
    }
    for session in sessions {
        session
            .round_trip(request(session.session_id()))
            .await
            .unwrap();
        session.complete().await;
    }

    let elapsed = started.elapsed();
    eprintln!(
        "direct fixed routing baseline: {EXCHANGE_COUNT} exchanges in {elapsed:?} ({:.0} exchanges/s)",
        f64::from(EXCHANGE_COUNT) / elapsed.as_secs_f64(),
    );
    drain_task.abort();
}
