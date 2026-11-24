//! Client sessions over dedicated connections.
//!
//! Dedicated sessions run one TACACS+ exchange or sequential conversation over
//! a single unshared transport when single-connection mode is disabled or the
//! server previously declined single-connection capability.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use tokio::sync::Mutex;

use tacacsrs_protocol::packet::{Packet, PacketTrait};

use crate::connection::{BoxedDedicatedConnection, DedicatedConnection};
use crate::exchange_error::{ProtocolFailure, protocol_failure};
use crate::session::random_nonzero_session_id;
use crate::transport::{BoxedTransport, Transport};

pub(crate) struct DedicatedSession {
    connection: Mutex<Option<BoxedDedicatedConnection>>,
    session_id: u32,
    expected_response_sequence: Mutex<Option<u8>>,
    complete: AtomicBool,
    counters: Option<crate::ServerCounters>,
}

impl DedicatedSession {
    pub(crate) fn new(transport: BoxedTransport, obfuscation_key: Option<&[u8]>) -> Self {
        Self {
            counters: transport.counters(),
            connection: Mutex::new(Some(DedicatedConnection::new(transport, obfuscation_key))),
            session_id: random_nonzero_session_id(),
            expected_response_sequence: Mutex::new(None),
            complete: AtomicBool::new(false),
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
        let packet = match connection
            .as_mut()
            .context("dedicated TACACS+ session is already complete")?
            .read_packet()
            .await
        {
            Ok(packet) => packet,
            Err(error) => {
                if error.is::<ProtocolFailure>() {
                    self.record_malformed_response();
                    connection.take();
                }
                return Err(error);
            }
        };

        if let Err(error) = self.validate_response_header(&packet).await {
            self.record_malformed_response();
            connection.take();
            return Err(error);
        }
        if packet.header().seq_no == 2 {
            if let Some(counters) = &self.counters {
                counters.single_connect(false);
            }
        }
        Ok(packet)
    }

    pub(crate) async fn reject_malformed_response(&self) {
        self.record_malformed_response();
        self.connection.lock().await.take();
    }

    fn record_malformed_response(&self) {
        if let Some(counters) = &self.counters {
            counters.disconnect_reason(crate::DisconnectReason::MalformedPacket);
        }
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

        if let Some(mut connection) = self.connection.lock().await.take() {
            connection.shutdown().await;
        }
    }

    pub(crate) fn record_timeout(&self) {
        if let Some(counters) = &self.counters {
            counters.disconnect_reason(crate::DisconnectReason::NoResponse);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tacacsrs_protocol::enumerations::{
        TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_protocol::header::Header;
    use tacacsrs_protocol::packet::{Packet, PacketTrait};

    use super::DedicatedSession;
    use crate::exchange_error::ProtocolFailure;
    use crate::transport::BoxedTransport;
    use crate::transport::mock::MockTransport;

    struct PendingShutdown {
        entered: Arc<std::sync::atomic::AtomicBool>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl crate::transport::Transport for PendingShutdown {
        type ReadHalf = tokio::io::Empty;
        type WriteHalf = Self;

        fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
            (tokio::io::empty(), self)
        }
    }

    impl tokio::io::AsyncWrite for PendingShutdown {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.entered
                .store(true, std::sync::atomic::Ordering::Release);
            std::task::Poll::Pending
        }
    }

    impl Drop for PendingShutdown {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[tokio::test]
    async fn malformed_response_discards_pending_shutdown_without_polling_it() {
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let session = DedicatedSession::new(
            BoxedTransport::new(PendingShutdown {
                entered: entered.clone(),
                dropped: dropped.clone(),
            }),
            None,
        );

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            session.reject_malformed_response(),
        )
        .await
        .unwrap();

        assert!(!entered.load(std::sync::atomic::Ordering::Acquire));
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
        assert!(session.connection.lock().await.is_none());
        session.complete().await;
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
            let session = DedicatedSession::new(BoxedTransport::new(transport.unwrap()), None);
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
    async fn dedicated_session_respects_disabled_single_connection_config() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();
        let session = DedicatedSession::new(BoxedTransport::new(mock), None);
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
        let session = DedicatedSession::new(BoxedTransport::new(mock), None);
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
}
