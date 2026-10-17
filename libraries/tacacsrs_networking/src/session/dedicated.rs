//! Client sessions over dedicated connections.
//!
//! A dedicated session can carry a [`SingleConnectPromotion`] when the server
//! configuration requested TACACS+ single-connection mode. The session still
//! runs as a normal request/response exchange. The promotion transfers the
//! connection after the session completes.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use tokio::sync::Mutex;

use tacacsrs_protocol::enumerations::TacacsFlags;
use tacacsrs_protocol::packet::{Packet, PacketTrait};

use crate::connection::{BoxedDedicatedConnection, DedicatedConnection};
use crate::session::random_nonzero_session_id;
use crate::single_connect::SingleConnectPromotion;
use crate::transport::{BoxedTransport, Transport};

pub(crate) struct DedicatedSession {
    connection: Mutex<Option<BoxedDedicatedConnection>>,
    session_id: u32,
    expected_response_sequence: Mutex<Option<u8>>,
    complete: AtomicBool,
    single_connect_promotion: std::sync::Mutex<Option<SingleConnectPromotion>>,
    counters: Option<crate::ServerCounters>,
}

impl DedicatedSession {
    pub(crate) fn new(
        transport: BoxedTransport,
        obfuscation_key: Option<&[u8]>,
        single_connect_promotion: Option<SingleConnectPromotion>,
    ) -> Self {
        Self {
            counters: transport.counters(),
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
            if let Some(counters) = &self.counters {
                counters.disconnect_reason(crate::DisconnectReason::MalformedPacket);
            }
            connection.take();
            return Err(error);
        }
        let promotion = self
            .single_connect_promotion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if packet.header().seq_no == 2 {
            if let Some(counters) = &self.counters {
                counters.single_connect(
                    promotion.is_some()
                        && packet
                            .header()
                            .flags
                            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG),
                );
            }
        }
        if let Some(promotion) = promotion.as_ref() {
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

    pub(crate) fn record_timeout(&self) {
        if let Some(counters) = &self.counters {
            counters.disconnect_reason(crate::DisconnectReason::NoResponse);
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
        let cache = Arc::new(crate::single_connect::SharedConnectionCache::default());
        let promotion = SingleConnectPromotion::begin(cache.clone(), state.clone()).unwrap();
        promotion.observe_server_response(&test_packet(
            TEST_SESSION_ID,
            2,
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
            b"reply",
        ));
        let session =
            DedicatedSession::new(BoxedTransport::new(MockTransport::new()), None, Some(promotion));
        let locked_cache = cache.lock_for_test().await;
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
        drop(locked_cache);
        assert!(cache.current().await.is_none());
    }

    #[tokio::test]
    async fn cancelled_shutdown_releases_pending_probe_and_preserves_unsupported_result() {
        use std::io;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll};

        use tokio::io::AsyncWrite;

        use crate::transport::Transport;

        struct PendingShutdown {
            entered: Arc<AtomicBool>,
            dropped: Arc<AtomicBool>,
        }

        impl Transport for PendingShutdown {
            type ReadHalf = tokio::io::Empty;
            type WriteHalf = Self;

            fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
                (tokio::io::empty(), self)
            }
        }

        impl AsyncWrite for PendingShutdown {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(bytes.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.entered.store(true, Ordering::Release);
                Poll::Pending
            }
        }

        impl Drop for PendingShutdown {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        for unsupported in [false, true] {
            let state = Arc::new(NegotiationState::new(SingleConnectionState::Initial));
            let cache = Arc::default();
            let promotion =
                SingleConnectPromotion::begin(Arc::clone(&cache), state.clone()).unwrap();
            if unsupported {
                promotion.observe_server_response(&test_packet(
                    TEST_SESSION_ID,
                    2,
                    TacacsFlags::empty(),
                    b"reply",
                ));
            }
            let entered = Arc::new(AtomicBool::new(false));
            let dropped = Arc::new(AtomicBool::new(false));
            let session = DedicatedSession::new(
                BoxedTransport::new(PendingShutdown {
                    entered: entered.clone(),
                    dropped: dropped.clone(),
                }),
                None,
                Some(promotion),
            );
            let mut completion = Box::pin(session.complete());
            assert!(futures::poll!(&mut completion).is_pending());
            assert!(entered.load(Ordering::Acquire));
            assert!(!dropped.load(Ordering::Acquire));
            let mut current = Box::pin(cache.current());
            assert!(matches!(futures::poll!(&mut current), Poll::Ready(None)));
            drop(completion);
            assert!(dropped.load(Ordering::Acquire));
            assert!(session.connection.lock().await.is_none());
            assert!(session.single_connect_promotion.lock().unwrap().is_none());
            assert_eq!(
                state.snapshot(),
                if unsupported {
                    SingleConnectionState::NotSupported
                } else {
                    SingleConnectionState::Initial
                }
            );
        }
    }

    #[tokio::test]
    async fn only_the_first_reply_decides_probe_support() {
        for first in [
            TacacsFlags::empty(),
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        ] {
            let state = Arc::new(NegotiationState::new(SingleConnectionState::Initial));
            let cache = Arc::default();
            let promotion =
                SingleConnectPromotion::begin(Arc::clone(&cache), state.clone()).unwrap();
            promotion.observe_server_response(&test_packet(TEST_SESSION_ID, 2, first, b"reply"));
            promotion.observe_server_response(&test_packet(
                TEST_SESSION_ID,
                4,
                first ^ TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                b"reply",
            ));
            promotion
                .promote_if_confirmed(crate::connection::DedicatedConnection::new(
                    BoxedTransport::new(MockTransport::new()),
                    None,
                ))
                .await;
            let supported = first.contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG);
            assert_eq!(cache.current().await.is_some(), supported);
            assert_eq!(
                state.snapshot(),
                if supported {
                    SingleConnectionState::Supported
                } else {
                    SingleConnectionState::NotSupported
                }
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

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (transport, peer) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept(),
        );
        let mut peer = peer.unwrap().0;
        let session = DedicatedSession::new(BoxedTransport::new(transport.unwrap()), None, None);
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
            &test_packet(session_id, 4, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, b"wrong sequence")
                .to_bytes(),
        )
        .await
        .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), session.receive_packet())
            .await
            .expect("invalid headers must not deadlock the connection lock")
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("unexpected TACACS+ response header"));
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        session.complete().await;
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
        assert!(shared_connection.current().await.is_none());
        assert_eq!(single_connection_state.snapshot(), SingleConnectionState::NotSupported);
    }

    #[tokio::test]
    async fn first_reply_controls_multi_round_promotion() {
        for first_supports_sharing in [true, false] {
            let mock = MockTransport::new();
            let coordinator = mock.coordinator();
            let shared_connection = Arc::default();
            let state = Arc::new(NegotiationState::new(SingleConnectionState::Initial));
            let session = DedicatedSession::new(
                BoxedTransport::new(mock),
                None,
                SingleConnectPromotion::begin(Arc::clone(&shared_connection), Arc::clone(&state)),
            );
            for (request_sequence, supports_sharing) in
                [(1, first_supports_sharing), (3, !first_supports_sharing)]
            {
                let mut reply_flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
                if supports_sharing {
                    reply_flags |= TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
                }
                coordinator
                    .add_reply(test_packet(
                        session.session_id(),
                        request_sequence + 1,
                        reply_flags,
                        b"reply",
                    ))
                    .await
                    .unwrap();
                session
                    .send_packet(test_packet(
                        session.session_id(),
                        request_sequence,
                        TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                        b"request",
                    ))
                    .await
                    .unwrap();
                session.receive_packet().await.unwrap();
            }
            session.complete().await;
            assert_eq!(shared_connection.current().await.is_some(), first_supports_sharing);
            assert_eq!(
                state.snapshot(),
                if first_supports_sharing {
                    SingleConnectionState::Supported
                } else {
                    SingleConnectionState::NotSupported
                }
            );
        }
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
            .current()
            .await
            .expect("single-connect response must cache the upgraded connection");
        assert_eq!(single_connection_state.snapshot(), SingleConnectionState::Supported);
        assert_eq!(connection.single_connection_state(), SingleConnectionState::Supported);
    }
}
