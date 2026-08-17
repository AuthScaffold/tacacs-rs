//! Client sessions over dedicated connections.
//!
//! A dedicated session may carry a [`SingleConnectPromotion`] when the server
//! configuration requested TACACS+ single-connection mode. The session still
//! runs as a normal request/response exchange; promotion is deferred until the
//! session completes and the connection can be transferred safely.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, RwLock};

use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use crate::runtime::{DedicatedConnection, MultiplexedConnection};
use crate::single_connect::SingleConnectionState;
use crate::session::random_nonzero_session_id;
use crate::transport::BoxedTransport;

type BoxedDedicatedConnection =
    DedicatedConnection<Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>>;

const SINGLE_CONNECT_RESPONSE_PENDING: u8 = 0;
const SINGLE_CONNECT_RESPONSE_UNSUPPORTED: u8 = 1;
const SINGLE_CONNECT_RESPONSE_SUPPORTED: u8 = 2;

/// Deferred promotion from a dedicated connection to a cached shared connection.
///
/// This is the callback carried by a dedicated session during TACACS+
/// single-connection negotiation. It records the server response synchronously
/// when a packet arrives. It does not convert the connection at that point. The
/// dedicated session owns the reader and writer halves until completion.
///
/// ```text
/// send request with single-connect flag
///     |
///     v
/// [Pending]
///     |
///     +-- response has flag ----> [Supported]
///     |                              |
///     |                              v
///     |                      complete session
///     |                              |
///     |                              v
///     |                      upgrade and cache shared connection
///     |
///     +-- response lacks flag ---> [Unsupported]
///                                    |
///                                    v
///                            mark NotSupported and drop connection
/// ```
pub(crate) struct SingleConnectPromotion {
    shared_connection: Arc<RwLock<Option<Arc<MultiplexedConnection>>>>,
    state: Arc<RwLock<SingleConnectionState>>,
    response: AtomicU8,
}

impl SingleConnectPromotion {
    pub(crate) fn new(
        shared_connection: Arc<RwLock<Option<Arc<MultiplexedConnection>>>>,
        state: Arc<RwLock<SingleConnectionState>>,
    ) -> Self {
        Self {
            shared_connection,
            state,
            response: AtomicU8::new(SINGLE_CONNECT_RESPONSE_PENDING),
        }
    }

    fn observe_server_response(&self, packet: &Packet) {
        let response = if packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
        {
            SINGLE_CONNECT_RESPONSE_SUPPORTED
        } else {
            SINGLE_CONNECT_RESPONSE_UNSUPPORTED
        };

        self.response.store(response, Ordering::Release);
    }

    async fn promote_if_confirmed(&self, connection: BoxedDedicatedConnection) {
        match self.response.load(Ordering::Acquire) {
            SINGLE_CONNECT_RESPONSE_SUPPORTED => {
                if self.record_server_result(true).await {
                    *self.shared_connection.write().await = Some(connection.upgrade());
                }
            }
            SINGLE_CONNECT_RESPONSE_UNSUPPORTED => {
                self.record_server_result(false).await;
            }
            SINGLE_CONNECT_RESPONSE_PENDING => {}
            _ => unreachable!("invalid single-connect response state"),
        }
    }

    async fn record_server_result(&self, supported: bool) -> bool {
        let mut state = self.state.write().await;
        let new_state = if supported {
            SingleConnectionState::Supported
        } else {
            SingleConnectionState::NotSupported
        };

        if *state == SingleConnectionState::NotSupported
            && new_state == SingleConnectionState::Supported
        {
            log::debug!(
                target: "tacacsrs_networking::single_connect",
                "Ignored late single-connect support confirmation because the state is NotSupported",
            );
            return false;
        }

        if *state != new_state {
            log::info!(
                target: "tacacsrs_networking::single_connect",
                "Single-connection state changed from {:?} to {:?}",
                *state,
                new_state,
            );
            *state = new_state;
        }

        supported
    }
}

pub(crate) struct DedicatedSession {
    connection: Mutex<Option<BoxedDedicatedConnection>>,
    session_id: u32,
    expected_response_sequence: Mutex<Option<u8>>,
    complete: AtomicBool,
    single_connect_promotion: Option<SingleConnectPromotion>,
}

impl DedicatedSession {
    pub(crate) fn new(
        transport: BoxedTransport,
        obfuscation_key: Option<&[u8]>,
        single_connect_promotion: Option<SingleConnectPromotion>,
    ) -> Self {
        Self {
            connection: Mutex::new(Some(DedicatedConnection::new(transport, obfuscation_key))),
            session_id: random_nonzero_session_id(),
            expected_response_sequence: Mutex::new(None),
            complete: AtomicBool::new(false),
            single_connect_promotion,
        }
    }

    pub(crate) const fn session_id(&self) -> u32 {
        self.session_id
    }

    pub(crate) async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
        if packet.header().session_id != self.session_id {
            anyhow::bail!(
                "dedicated session {} cannot send packet for session {}",
                self.session_id,
                packet.header().session_id,
            );
        }

        let response_sequence = packet.header().seq_no.wrapping_add(1);
        let packet = match &self.single_connect_promotion {
            Some(_) => with_single_connect_flag(&packet)?,
            None => packet,
        };

        {
            let mut expected_response_sequence = self.expected_response_sequence.lock().await;
            if expected_response_sequence.is_some() {
                anyhow::bail!(
                    "dedicated TACACS+ session {} already has a request awaiting response",
                    self.session_id,
                );
            }
            *expected_response_sequence = Some(response_sequence);
        }

        let write_result = {
            let mut connection = self.connection.lock().await;
            match connection.as_mut() {
                Some(connection) => connection.write_packet(packet).await,
                None => Err(anyhow::anyhow!("dedicated TACACS+ session is already complete")),
            }
        };

        if let Err(error) = write_result {
            *self.expected_response_sequence.lock().await = None;
            return Err(error);
        }

        Ok(())
    }

    pub(crate) async fn receive_packet(&self) -> anyhow::Result<Packet> {
        let mut connection = self.connection.lock().await;
        let connection = connection
            .as_mut()
            .context("dedicated TACACS+ session is already complete")?;
        let packet = connection.read_packet().await?;

        self.validate_response_header(&packet).await?;
        if let Some(promotion) = &self.single_connect_promotion {
            promotion.observe_server_response(&packet);
        }
        Ok(packet)
    }

    async fn validate_response_header(&self, packet: &Packet) -> anyhow::Result<()> {
        let expected_sequence = self
            .expected_response_sequence
            .lock()
            .await
            .take()
            .context("no TACACS+ request is awaiting a response")?;
        let header = packet.header();

        if header.session_id != self.session_id || header.seq_no != expected_sequence {
            self.connection.lock().await.take();
            anyhow::bail!(
                "unexpected TACACS+ response header: session_id={:#x}, seq_no={}, expected_session_id={:#x}, expected_seq_no={}",
                header.session_id,
                header.seq_no,
                self.session_id,
                expected_sequence,
            );
        }

        Ok(())
    }

    pub(crate) async fn complete(&self) {
        if self.complete.swap(true, Ordering::AcqRel) {
            return;
        }

        let Some(connection) = self.connection.lock().await.take() else {
            return;
        };

        if let Some(promotion) = &self.single_connect_promotion {
            promotion.promote_if_confirmed(connection).await;
        }
    }
}

fn with_single_connect_flag(packet: &Packet) -> anyhow::Result<Packet> {
    let mut header = packet.header().clone();
    header.flags |= TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
    Packet::new(header, packet.body().to_vec())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use tacacsrs_messages::enumerations::{
        TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::{Packet, PacketTrait};

    use super::{DedicatedSession, SingleConnectPromotion, with_single_connect_flag};
    use crate::single_connect::SingleConnectionState;
    use crate::transport::BoxedTransport;
    use crate::transport::mock::MockTransport;

    const TEST_SESSION_ID: u32 = 0xCAFE_BABE;

    fn test_packet(session_id: u32, seq_no: u8, flags: TacacsFlags, body: &[u8]) -> Packet {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no,
                flags,
                session_id,
                length: u32::try_from(body.len()).unwrap(),
            },
            body.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn adds_single_connect_flag_without_changing_body() {
        let packet =
            test_packet(TEST_SESSION_ID, 1, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, b"request");
        let updated = with_single_connect_flag(&packet).unwrap();

        assert!(updated
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        assert_eq!(updated.body(), packet.body());
    }

    #[tokio::test]
    async fn dedicated_session_adds_single_connect_flag_and_does_not_cache_when_absent() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();
        let shared_connection = Arc::default();
        let single_connection_state = Arc::new(RwLock::new(SingleConnectionState::Initial));
        let session = DedicatedSession::new(
            BoxedTransport::new(mock),
            None,
            Some(SingleConnectPromotion::new(
                Arc::clone(&shared_connection),
                Arc::clone(&single_connection_state),
            )),
        );
        let session_id = session.session_id();
        coordinator
            .add_reply(test_packet(session_id, 2, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, b"reply"))
            .await
            .unwrap();

        session
            .send_packet(test_packet(
                session_id,
                1,
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                b"request",
            ))
            .await
            .unwrap();
        let _response = session.receive_packet().await.unwrap();
        session.complete().await;

        let requests = coordinator
            .get_requests_for_session(session_id)
            .await
            .unwrap();
        assert!(requests[&1]
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        assert!(shared_connection.read().await.is_none());
        assert_eq!(*single_connection_state.read().await, SingleConnectionState::NotSupported);
    }

    #[tokio::test]
    async fn dedicated_session_respects_disabled_single_connection_config() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();
        let session = DedicatedSession::new(BoxedTransport::new(mock), None, None);
        let session_id = session.session_id();
        coordinator
            .add_reply(test_packet(
                session_id,
                2,
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                b"reply",
            ))
            .await
            .unwrap();

        session
            .send_packet(test_packet(
                session_id,
                1,
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                b"request",
            ))
            .await
            .unwrap();
        let _response = session.receive_packet().await.unwrap();
        session.complete().await;

        let requests = coordinator
            .get_requests_for_session(session_id)
            .await
            .unwrap();
        assert!(!requests[&1]
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
    }

    #[tokio::test]
    async fn dedicated_session_rejects_send_while_response_is_pending() {
        let mock = MockTransport::new();
        let session = DedicatedSession::new(BoxedTransport::new(mock), None, None);
        let session_id = session.session_id();

        session
            .send_packet(test_packet(
                session_id,
                1,
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                b"request",
            ))
            .await
            .unwrap();

        let error = session
            .send_packet(test_packet(
                session_id,
                3,
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                b"next request",
            ))
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("already has a request awaiting response"));
    }

    #[tokio::test]
    async fn dedicated_session_upgrades_and_caches_when_single_connect_is_echoed() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();
        let shared_connection = Arc::default();
        let single_connection_state = Arc::new(RwLock::new(SingleConnectionState::Initial));
        let session = DedicatedSession::new(
            BoxedTransport::new(mock),
            None,
            Some(SingleConnectPromotion::new(
                Arc::clone(&shared_connection),
                Arc::clone(&single_connection_state),
            )),
        );
        let session_id = session.session_id();
        coordinator
            .add_reply(test_packet(
                session_id,
                2,
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                b"reply",
            ))
            .await
            .unwrap();

        session
            .send_packet(test_packet(
                session_id,
                1,
                TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                b"request",
            ))
            .await
            .unwrap();
        let _response = session.receive_packet().await.unwrap();
        session.complete().await;

        let connection = shared_connection
            .read()
            .await
            .as_ref()
            .expect("single-connect response must cache the upgraded connection")
            .clone();
        assert_eq!(*single_connection_state.read().await, SingleConnectionState::Supported);
        assert_eq!(connection.single_connection_state().await, SingleConnectionState::Supported);
    }
}
