use std::sync::Arc;
use std::time::Instant;

use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use super::MultiplexedConnection;

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
#[ignore = "manual multiplexed routing baseline"]
async fn shared_session_routing_burst_baseline() {
    const EXCHANGE_COUNT: usize = 512;

    let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None));
    let started = Instant::now();
    let mut sessions = Vec::with_capacity(EXCHANGE_COUNT);

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
        EXCHANGE_COUNT as f64 / elapsed.as_secs_f64(),
    );
}
