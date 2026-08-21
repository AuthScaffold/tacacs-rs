use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use super::DedicatedConnection;
use crate::single_connect::SingleConnectionState;
use crate::transport::mock::MockTransport;

const TEST_SESSION_ID: u32 = 0xDEAD_BEEF;

fn test_packet(seq_no: u8, flags: TacacsFlags, body: &[u8]) -> Packet {
    Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no,
            flags,
            session_id: TEST_SESSION_ID,
            length: u32::try_from(body.len()).unwrap(),
        },
        body.to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn write_and_read_packet_round_trip() {
    let mock = MockTransport::new();
    let coordinator = mock.coordinator();
    let reply = test_packet(2, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, b"reply");

    coordinator.add_reply(reply.clone()).await.unwrap();

    let mut connection = DedicatedConnection::new(mock, None);
    connection
        .write_packet(test_packet(1, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, b"request"))
        .await
        .unwrap();

    let response = connection.read_packet().await.unwrap();
    assert_eq!(response.header().session_id, TEST_SESSION_ID);
    assert_eq!(response.header().seq_no, 2);
    assert_eq!(response.body(), reply.body());

    let requests = coordinator
        .get_requests_for_session(TEST_SESSION_ID)
        .await
        .unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests.contains_key(&1));
}

#[tokio::test]
async fn write_packet_obfuscates_when_key_is_configured() {
    let key = b"test_secret";
    let mock = MockTransport::new();
    let coordinator = mock.coordinator();
    let reply = test_packet(2, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, b"reply").to_obfuscated(key);

    coordinator.add_reply(reply).await.unwrap();

    let mut connection = DedicatedConnection::new(mock, Some(key));
    connection
        .write_packet(test_packet(1, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, b"request"))
        .await
        .unwrap();
    let _response = connection.read_packet().await.unwrap();

    let requests = coordinator
        .get_requests_for_session(TEST_SESSION_ID)
        .await
        .unwrap();
    let captured = &requests[&1];
    assert!(
        !captured
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG),
        "captured request must be obfuscated"
    );
}

#[tokio::test]
async fn upgrade_reuses_stream_for_multiplexed_connection() {
    let mock = MockTransport::new();
    let coordinator = mock.coordinator();
    let reply = test_packet(
        2,
        TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        b"reply",
    );
    coordinator.add_reply(reply).await.unwrap();

    let mut dedicated = DedicatedConnection::new(mock, None);
    dedicated
        .write_packet(test_packet(
            1,
            TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
            b"request",
        ))
        .await
        .unwrap();
    let response = dedicated.read_packet().await.unwrap();
    assert!(response
        .header()
        .flags
        .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));

    let connection = dedicated.upgrade();
    assert_eq!(connection.single_connection_state(), SingleConnectionState::Supported);
}
