//! Client sessions over dedicated connections.
//!
//! A dedicated session can carry a [`SingleConnectPromotion`] when the server
//! configuration requested TACACS+ single-connection mode. The session still
//! runs as a normal request/response exchange. The promotion transfers the
//! connection after the session completes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use tacacsrs_protocol::enumerations::TacacsFlags;
use tacacsrs_protocol::packet::{Packet, PacketTrait};

use crate::client::SharedConnectionCache;
use crate::exchange_error::protocol_failure;
use crate::runtime::DedicatedConnection;
use crate::single_connect::NegotiationState;
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
    shared_connection: Arc<SharedConnectionCache>,
    cache_generation: u64,
    state: Arc<NegotiationState>,
    epoch: u64,
    response: AtomicU8,
}

impl SingleConnectPromotion {
    pub(crate) fn begin(
        shared_connection: Arc<SharedConnectionCache>,
        state: Arc<NegotiationState>,
    ) -> Option<Self> {
        let epoch = state.begin()?;
        Some(Self {
            cache_generation: shared_connection.generation.load(Ordering::Acquire),
            shared_connection,
            state,
            epoch,
            response: AtomicU8::new(SINGLE_CONNECT_RESPONSE_PENDING),
        })
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

        let _first = self.response.compare_exchange(
            SINGLE_CONNECT_RESPONSE_PENDING,
            response,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    async fn promote_if_confirmed(&self, mut connection: BoxedDedicatedConnection) {
        let supported = match self.response.load(Ordering::Acquire) {
            SINGLE_CONNECT_RESPONSE_SUPPORTED => true,
            SINGLE_CONNECT_RESPONSE_UNSUPPORTED => false,
            SINGLE_CONNECT_RESPONSE_PENDING => {
                connection.shutdown().await;
                return;
            }
            _ => unreachable!("invalid single-connect response state"),
        };
        let mut slot = self.shared_connection.slot.write().await;
        if self.shared_connection.closed.load(Ordering::Acquire)
            || self.cache_generation != self.shared_connection.generation.load(Ordering::Acquire)
        {
            return;
        }
        if supported {
            self.state.settle(self.epoch, true, || {
                *slot = Some(connection.upgrade());
            });
        } else {
            self.state.settle(self.epoch, false, || {});
            drop(slot);
            connection.shutdown().await;
        }
    }
}

impl Drop for SingleConnectPromotion {
    fn drop(&mut self) {
        self.state.abandon(self.epoch);
    }
}

pub(crate) struct DedicatedSession {
    connection: Mutex<Option<BoxedDedicatedConnection>>,
    session_id: u32,
    expected_response_sequence: Mutex<Option<u8>>,
    complete: AtomicBool,
    single_connect_promotion: std::sync::Mutex<Option<SingleConnectPromotion>>,
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
            single_connect_promotion: std::sync::Mutex::new(single_connect_promotion),
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
        let packet = match self
            .single_connect_promotion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
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
        let packet = connection
            .as_mut()
            .context("dedicated TACACS+ session is already complete")?
            .read_packet()
            .await?;

        if let Err(error) = self.validate_response_header(&packet).await {
            connection.take();
            return Err(error);
        }
        if let Some(promotion) = self
            .single_connect_promotion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
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
            return Err(protocol_failure(anyhow::anyhow!(
                "unexpected TACACS+ response header: session_id={:#x}, seq_no={}, expected_session_id={:#x}, expected_seq_no={}",
                header.session_id,
                header.seq_no,
                self.session_id,
                expected_sequence,
            )));
        }

        Ok(())
    }

    pub(crate) async fn complete(&self) {
        if self.complete.swap(true, Ordering::AcqRel) {
            return;
        }

        let promotion = self
            .single_connect_promotion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(mut connection) = self.connection.lock().await.take() else {
            return;
        };

        if let Some(promotion) = promotion {
            promotion.promote_if_confirmed(connection).await;
        } else {
            connection.shutdown().await;
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

    use tacacsrs_protocol::enumerations::{
        TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_protocol::header::Header;
    use tacacsrs_protocol::packet::{Packet, PacketTrait};

    use super::{DedicatedSession, SingleConnectPromotion, with_single_connect_flag};
    use crate::exchange_error::ProtocolFailure;
    use crate::single_connect::{NegotiationState, SingleConnectionState};
    use crate::transport::BoxedTransport;
    use crate::transport::mock::MockTransport;

    const TEST_SESSION_ID: u32 = 0xCAFE_BABE;

    #[tokio::test]
    async fn completion_without_a_reply_releases_negotiation() {
        let state = Arc::new(NegotiationState::new(SingleConnectionState::Initial));
        let session = DedicatedSession::new(
            BoxedTransport::new(MockTransport::new()),
            None,
            SingleConnectPromotion::begin(Arc::default(), state.clone()),
        );
        session.complete().await;
        assert_eq!(state.snapshot(), SingleConnectionState::Initial);
        assert!(session.connection.lock().await.is_none());
    }

    #[tokio::test]
    async fn cancelled_completion_releases_probe_while_session_is_retained() {
        let state = Arc::new(NegotiationState::new(SingleConnectionState::Initial));
        let cache = Arc::new(crate::client::SharedConnectionCache::default());
        let promotion = SingleConnectPromotion::begin(cache.clone(), state.clone()).unwrap();
        promotion.observe_server_response(&test_packet(
            TEST_SESSION_ID,
            2,
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
            b"reply",
        ));
        let session =
            DedicatedSession::new(BoxedTransport::new(MockTransport::new()), None, Some(promotion));
        let locked_cache = cache.slot.write().await;
        {
            let mut completion = Box::pin(session.complete());
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(completion.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        assert_eq!(state.snapshot(), SingleConnectionState::Initial);
        assert!(session.connection.lock().await.is_none());
        assert!(locked_cache.is_none());
    }

    #[test]
    fn only_the_first_reply_decides_probe_support() {
        for first in [
            TacacsFlags::empty(),
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        ] {
            let state = Arc::new(NegotiationState::new(SingleConnectionState::Initial));
            let promotion = SingleConnectPromotion::begin(Arc::default(), state).unwrap();
            promotion.observe_server_response(&test_packet(TEST_SESSION_ID, 2, first, b"reply"));
            let expected = promotion
                .response
                .load(std::sync::atomic::Ordering::Acquire);
            promotion.observe_server_response(&test_packet(
                TEST_SESSION_ID,
                4,
                first ^ TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                b"reply",
            ));
            assert_eq!(
                promotion
                    .response
                    .load(std::sync::atomic::Ordering::Acquire),
                expected
            );
        }
    }

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
    async fn invalid_reply_header_releases_transport_without_deadlocking() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use crate::{PacketReader, PacketReadResult};

        for (session_delta, sequence) in [(0, 4), (1, 2)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (transport, peer) = tokio::join!(
                tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept(),
            );
            let mut peer = peer.unwrap().0;
            let session =
                DedicatedSession::new(BoxedTransport::new(transport.unwrap()), None, None);
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
            assert!(matches!(
                PacketReader::new(None).read_packet(&mut peer).await,
                PacketReadResult::Success(_)
            ));
            peer.write_all(
                &test_packet(
                    session_id.wrapping_add(session_delta),
                    sequence,
                    TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                    b"invalid header",
                )
                .to_bytes(),
            )
            .await
            .unwrap();
            let error = tokio::time::timeout(Duration::from_secs(1), session.receive_packet())
                .await
                .expect("invalid headers must not deadlock the connection lock")
                .unwrap_err();
            assert!(error.is::<ProtocolFailure>(), "unexpected error: {error:#}");
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            session.complete().await;
        }
    }

    #[tokio::test]
    async fn dedicated_session_adds_single_connect_flag_and_does_not_cache_when_absent() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();
        let shared_connection = Arc::default();
        let single_connection_state =
            Arc::new(NegotiationState::new(SingleConnectionState::Initial));
        let session = DedicatedSession::new(
            BoxedTransport::new(mock),
            None,
            SingleConnectPromotion::begin(
                Arc::clone(&shared_connection),
                Arc::clone(&single_connection_state),
            ),
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
        assert!(shared_connection.slot.read().await.is_none());
        assert_eq!(single_connection_state.snapshot(), SingleConnectionState::NotSupported);
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
    async fn late_promotion_retires_after_last_cache_owner_drops() {
        use std::time::Duration;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::{PacketReader, PacketReadResult};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (transport, peer) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept(),
        );
        let mut peer = peer.unwrap().0;
        let shared_connection = Arc::default();
        let session = DedicatedSession::new(
            BoxedTransport::new(transport.unwrap()),
            None,
            SingleConnectPromotion::begin(
                Arc::clone(&shared_connection),
                Arc::new(NegotiationState::new(SingleConnectionState::Initial)),
            ),
        );
        drop(shared_connection);
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
        assert!(matches!(
            PacketReader::new(None).read_packet(&mut peer).await,
            PacketReadResult::Success(_)
        ));
        let reply = test_packet(
            session_id,
            2,
            TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
            b"reply",
        );
        peer.write_all(&reply.to_bytes()).await.unwrap();
        session.receive_packet().await.unwrap();
        session.complete().await;
        drop(session);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn dedicated_session_upgrades_and_caches_when_single_connect_is_echoed() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();
        let shared_connection = Arc::default();
        let single_connection_state =
            Arc::new(NegotiationState::new(SingleConnectionState::Initial));
        let session = DedicatedSession::new(
            BoxedTransport::new(mock),
            None,
            SingleConnectPromotion::begin(
                Arc::clone(&shared_connection),
                Arc::clone(&single_connection_state),
            ),
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
            .slot
            .read()
            .await
            .as_ref()
            .expect("single-connect response must cache the upgraded connection")
            .clone();
        assert_eq!(single_connection_state.snapshot(), SingleConnectionState::Supported);
        assert_eq!(connection.single_connection_state(), SingleConnectionState::Supported);
    }
}
