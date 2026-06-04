//! [`MockTransport`] — the entry point for the mock transport infrastructure.
//!
//! See the [module-level documentation](super) for the overall architecture.
//!
//! This file contains `MockTransport` itself (which implements [`Transport`]),
//! the background **write processor** task, and integration tests that exercise
//! the full round-trip through all mock components.

use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use tacacsrs_messages::packet::PacketTrait;

use crate::codec::{PacketReadResult, PacketReader, PacketReaderTrait};
use crate::transport::abstractions::Transport;

use super::channel_reader::ChannelReader;
use super::mock_read_half::MockReadHalf;
use super::mock_state::MockState;
use super::mock_transport_coordinator::MockTransportCoordinator;
use super::mock_write_half::MockWriteHalf;

/// A mock transport that implements [`Transport`] for integration testing.
///
/// Construct one with [`MockTransport::new()`], obtain a [`MockTransportCoordinator`]
/// via [`MockTransport::coordinator()`], then pass the transport into
/// [`MultiplexedConnection`](crate::runtime::MultiplexedConnection).
///
/// Since [`split`](Transport::split) consumes `self`, the compiler enforces
/// that it can only be called once.
#[derive(Debug)]
pub(crate) struct MockTransport {
    /// Shared state holding replies and captured requests.
    /// Also accessed by [`MockTransportCoordinator`].
    state: Arc<Mutex<MockState>>,

    /// Sender side of the "read" channel. The write processor pushes reply bytes
    /// here so that [`MockReadHalf`] can receive them.
    read_tx: mpsc::UnboundedSender<Vec<u8>>,

    /// Receiver side of the "read" channel, consumed when
    /// [`split`](Transport::split) is called.
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    /// Creates a new mock transport with empty state (no replies, no requests).
    ///
    /// After construction, call [`coordinator()`](Self::coordinator) to get a handle
    /// for configuring replies and inspecting captured requests.
    #[must_use]
    pub(crate) fn new() -> Self {
        // This channel carries reply bytes from the write processor → MockReadHalf.
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        Self {
            state: Arc::new(Mutex::new(MockState::default())),
            read_tx,
            read_rx,
        }
    }

    /// Returns a [`MockTransportCoordinator`] handle for configuring and inspecting
    /// this transport.
    ///
    /// The coordinator shares the same `MockState` and can be used **before and
    /// during** a connection run — for example to add replies after the connection
    /// has already started processing.
    ///
    /// Multiple coordinators may be created; they all share the same underlying state.
    #[must_use]
    pub(crate) fn coordinator(&self) -> MockTransportCoordinator {
        MockTransportCoordinator {
            state: Arc::clone(&self.state),
        }
    }

    /// Spawns the **write processor** — the heart of the mock transport.
    ///
    /// This is a `tokio::spawn`-ed async task that:
    ///
    /// 1. **Reads** complete TACACS+ packets from a [`ChannelReader`] that wraps
    ///    the byte channel fed by [`MockWriteHalf`]. Packet framing, header
    ///    parsing, and body reassembly are delegated to [`PacketReader`].
    /// 2. **Records** each parsed request in [`MockState::requests`] so tests
    ///    can inspect what the connection sent.
    /// 3. **Looks up** a matching reply in [`MockState::replies`] for the *next*
    ///    expected sequence number (`request_seq + 1`).
    /// 4. **Sends** the reply bytes to `read_tx`, which feeds [`MockReadHalf`].
    ///    If the reply has a configured delay, a nested `tokio::spawn` sleeps first.
    ///
    /// The task exits when the [`ChannelReader`] returns EOF (i.e. [`MockWriteHalf`]
    /// is dropped and the channel closes).
    ///
    /// # Why a background task?
    ///
    /// This avoids holding the [`MockState`] mutex inside a `poll_write` call.
    /// Instead, `poll_write` just pushes bytes into a channel (lock-free), and
    /// this task does the async `.lock().await` on its own, which is safe because
    /// it runs as a normal async future — not inside a `poll_*` method.
    fn spawn_write_processor(
        write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        state: Arc<Mutex<MockState>>,
        read_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            // Wrap the channel in an AsyncRead so PacketReader can consume it
            // as a byte stream, handling framing and reassembly for us.
            //
            // NOTE: The reader is created **without** an obfuscation key.
            // This means the mock transport operates like a network capture
            // (pcap) — it records and replays raw bytes without attempting
            // to deobfuscate them. If tests need to inspect the cleartext
            // body of captured request packets, they must deobfuscate
            // manually after retrieving them from `MockState::requests`.
            let packet_reader = PacketReader::new(None);
            let mut reader = ChannelReader::new(write_rx);

            loop {
                match packet_reader.read_packet(&mut reader).await {
                    PacketReadResult::Success(request) => {
                        let session_id = request.header().session_id;
                        let request_seq = request.header().seq_no;
                        // In TACACS+, the server reply has seq_no = request_seq + 1.
                        let reply_seq = request_seq.saturating_add(1);

                        log::info!(
                            "mock write processor: captured request for session {session_id} seq_no {request_seq}"
                        );

                        // Acquire the shared state to record the request and look up
                        // the reply. This is an async lock — it cooperates with the
                        // tokio runtime.
                        let mut state = state.lock().await;

                        state
                            .requests
                            .entry(session_id)
                            .or_default()
                            .insert(request_seq, request);

                        // Remove the reply (consumed — each reply fires once).
                        let reply = state
                            .replies
                            .get_mut(&session_id)
                            .and_then(|reply_map| reply_map.remove(&reply_seq));

                        // Drop the lock before doing I/O or spawning tasks.
                        drop(state);

                        if let Some(reply_config) = reply {
                            if let Some(delay) = reply_config.delay {
                                log::info!(
                                    "mock write processor: scheduling delayed reply ({delay:?}) for session {session_id} seq_no {reply_seq}"
                                );
                                let tx = read_tx.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(delay).await;
                                    log::info!(
                                        "mock write processor: sending delayed reply for session {session_id} seq_no {reply_seq}"
                                    );
                                    let _ = tx.send(reply_config.bytes);
                                });
                            } else {
                                log::info!(
                                    "mock write processor: sending reply for session {session_id} seq_no {reply_seq}"
                                );
                                let _ = read_tx.send(reply_config.bytes);
                            }
                        } else {
                            log::debug!(
                                "mock write processor: no reply configured for session {session_id} seq_no {reply_seq}"
                            );
                        }
                    }
                    // Channel closed (EOF) — MockWriteHalf was dropped.
                    PacketReadResult::HeaderReadError(_) => {
                        log::info!("mock write processor: channel closed (EOF), exiting");
                        break;
                    }
                    // Any other error is unexpected in a mock — surface it loudly.
                    PacketReadResult::HeaderParseError(e) => panic!(
                        "mock transport write processor: header parse error: {e}"
                    ),
                    PacketReadResult::BodyLengthExceeded { session_id, body_length, max_length } => panic!(
                        "mock transport write processor: body length {body_length} exceeds max {max_length} for session {session_id}"
                    ),
                    PacketReadResult::BodyReadError { session_id, error } => panic!(
                        "mock transport write processor: body read error for session {session_id}: {error}"
                    ),
                    PacketReadResult::PacketCreateError { session_id, error } => panic!(
                        "mock transport write processor: packet create error for session {session_id}: {error}"
                    ),
                }
            }
        })
    }
}

impl Transport for MockTransport {
    type ReadHalf = MockReadHalf;
    type WriteHalf = MockWriteHalf;

    /// Splits the transport into a read half and a write half, and spawns the
    /// background write processor task.
    ///
    /// This consumes `self`, so it can only be called once (enforced by the
    /// compiler — no runtime checks needed).
    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        log::info!("mock transport: splitting into read and write halves");

        // Create the write channel: MockWriteHalf → write processor task.
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Spawn the background task that processes written bytes.
        // It shares `self.state` with the coordinator and pushes reply bytes
        // into `self.read_tx` which feeds the MockReadHalf.
        let processor_handle =
            Self::spawn_write_processor(write_rx, Arc::clone(&self.state), self.read_tx);

        (MockReadHalf::new(self.read_rx), MockWriteHalf::new(write_tx, processor_handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use tacacsrs_messages::enumerations::{
        TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::Packet;

    /// Helper: creates a TACACS+ Header for testing.
    fn test_header(session_id: u32, seq_no: u8, body_length: u32) -> Header {
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAuthentication,
            seq_no,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id,
            length: body_length,
        }
    }

    /// Helper: creates a complete TACACS+ Packet for testing.
    #[allow(clippy::cast_possible_truncation)] // test data is small
    fn test_packet(session_id: u32, seq_no: u8, body: Vec<u8>) -> Packet {
        let header = test_header(session_id, seq_no, body.len() as u32);
        Packet::new(header, body).unwrap()
    }

    // ── Construction ──────────────────────────────────────────────────

    #[test]
    fn test_new_creates_transport() {
        let transport = MockTransport::new();
        // Should be able to obtain a coordinator without panicking.
        let _coordinator = transport.coordinator();
    }

    #[test]
    fn test_default_creates_transport() {
        let transport = MockTransport::default();
        let _coordinator = transport.coordinator();
    }

    // ── Split ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_split_returns_read_and_write_halves() {
        let transport = MockTransport::new();
        let (mut read_half, mut write_half) = transport.split();

        // Write half should accept bytes.
        let written = write_half.write(&[0u8; 4]).await.unwrap();
        assert_eq!(written, 4);

        // Shut down write half so read half eventually sees EOF.
        write_half.shutdown().await.unwrap();
        drop(write_half);

        // Read half should reach EOF (0 bytes) eventually.
        let mut buf = [0u8; 64];
        // Give the processor a moment to process and close.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let n = read_half.read(&mut buf).await.unwrap();
        // With no configured reply for the (invalid) bytes, we just get EOF.
        assert_eq!(n, 0);
    }

    // ── Write → Processor → Read (round-trip) ────────────────────────

    #[tokio::test]
    async fn test_write_request_receives_reply() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        // Build a request (seq 1) and a matching reply (seq 2).
        let request = test_packet(1000, 1, vec![0xAA, 0xBB]);
        let reply = test_packet(1000, 2, vec![0xCC, 0xDD]);

        coordinator.add_reply(reply.clone()).await.unwrap();

        let (mut read_half, mut write_half) = transport.split();

        // Write the request into the mock transport.
        write_half.write_all(&request.to_bytes()).await.unwrap();

        // Read the reply back from the read half.
        let reply_bytes = reply.to_bytes();
        let mut buf = vec![0u8; reply_bytes.len()];
        read_half.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, reply_bytes);
    }

    #[tokio::test]
    async fn test_request_is_captured() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        let body = vec![0x01, 0x02, 0x03];
        let request = test_packet(2000, 1, body.clone());
        let reply = test_packet(2000, 2, vec![0xFF]);

        coordinator.add_reply(reply).await.unwrap();

        let (mut read_half, mut write_half) = transport.split();

        write_half.write_all(&request.to_bytes()).await.unwrap();

        // Consume the reply so the processor has finished recording.
        let mut sink = vec![0u8; 128];
        let _ = read_half.read(&mut sink).await.unwrap();

        let requests = coordinator.get_requests_for_session(2000).await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests.contains_key(&1));
        assert_eq!(requests[&1].body(), &body);
    }

    #[tokio::test]
    async fn test_reply_is_consumed_after_delivery() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        let reply = test_packet(3000, 2, vec![0xDE, 0xAD]);
        coordinator.add_reply(reply.clone()).await.unwrap();

        // Before delivery, reply should be present.
        let before = coordinator.get_replies_for_session(3000).await.unwrap();
        assert_eq!(before.len(), 1);

        let (mut read_half, mut write_half) = transport.split();

        let request = test_packet(3000, 1, vec![0x00]);
        write_half.write_all(&request.to_bytes()).await.unwrap();

        // Read the reply to let the processor consume it.
        let mut buf = vec![0u8; reply.to_bytes().len()];
        read_half.read_exact(&mut buf).await.unwrap();

        // After delivery, no replies should remain.
        let after = coordinator.get_replies_for_session(3000).await;
        // Either no entry or empty map.
        assert!(after.is_err() || after.unwrap().is_empty(), "reply should have been consumed");
    }

    #[tokio::test]
    async fn test_no_reply_configured_still_captures_request() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        let (mut _read_half, mut write_half) = transport.split();

        let request = test_packet(4000, 1, vec![0x42]);
        write_half.write_all(&request.to_bytes()).await.unwrap();

        // Give the processor time to handle the packet.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let requests = coordinator.get_requests_for_session(4000).await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[&1].body(), &vec![0x42]);
    }

    // ── Multiple packets / sessions ──────────────────────────────────

    #[tokio::test]
    async fn test_multiple_requests_same_session() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        // Two request-reply pairs for the same session, different seq numbers.
        let req1 = test_packet(5000, 1, vec![0x01]);
        let reply1 = test_packet(5000, 2, vec![0x11]);
        let req2 = test_packet(5000, 3, vec![0x02]);
        let reply2 = test_packet(5000, 4, vec![0x22]);

        coordinator.add_reply(reply1.clone()).await.unwrap();
        coordinator.add_reply(reply2.clone()).await.unwrap();

        let (mut read_half, mut write_half) = transport.split();

        // Send first request then read its reply.
        write_half.write_all(&req1.to_bytes()).await.unwrap();
        let mut buf1 = vec![0u8; reply1.to_bytes().len()];
        read_half.read_exact(&mut buf1).await.unwrap();
        assert_eq!(buf1, reply1.to_bytes());

        // Send second request then read its reply.
        write_half.write_all(&req2.to_bytes()).await.unwrap();
        let mut buf2 = vec![0u8; reply2.to_bytes().len()];
        read_half.read_exact(&mut buf2).await.unwrap();
        assert_eq!(buf2, reply2.to_bytes());

        // Both requests should be captured.
        let requests = coordinator.get_requests_for_session(5000).await.unwrap();
        assert_eq!(requests.len(), 2);
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        let request_a = test_packet(6000, 1, vec![0xAA]);
        let reply_a = test_packet(6000, 2, vec![0xA1]);
        let request_b = test_packet(7000, 1, vec![0xBB]);
        let reply_b = test_packet(7000, 2, vec![0xB1]);

        coordinator.add_reply(reply_a.clone()).await.unwrap();
        coordinator.add_reply(reply_b.clone()).await.unwrap();

        let (mut read_half, mut write_half) = transport.split();

        // Write both requests.
        write_half.write_all(&request_a.to_bytes()).await.unwrap();
        write_half.write_all(&request_b.to_bytes()).await.unwrap();

        // Read both replies (order matches write order).
        let mut buf_a = vec![0u8; reply_a.to_bytes().len()];
        read_half.read_exact(&mut buf_a).await.unwrap();
        assert_eq!(buf_a, reply_a.to_bytes());

        let mut buf_b = vec![0u8; reply_b.to_bytes().len()];
        read_half.read_exact(&mut buf_b).await.unwrap();
        assert_eq!(buf_b, reply_b.to_bytes());

        // Each session should have its own captured request.
        let captured_a = coordinator.get_requests_for_session(6000).await.unwrap();
        assert_eq!(captured_a.len(), 1);
        let captured_b = coordinator.get_requests_for_session(7000).await.unwrap();
        assert_eq!(captured_b.len(), 1);
    }

    // ── Delayed replies ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_delayed_reply() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        let request = test_packet(8000, 1, vec![0x00]);
        let reply = test_packet(8000, 2, vec![0xFF]);

        coordinator
            .add_reply_with_delay(reply.clone(), Duration::from_millis(100))
            .await
            .unwrap();

        let (mut read_half, mut write_half) = transport.split();

        let start = Instant::now();
        write_half.write_all(&request.to_bytes()).await.unwrap();

        let mut buf = vec![0u8; reply.to_bytes().len()];
        read_half.read_exact(&mut buf).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(buf, reply.to_bytes());
        assert!(
            elapsed >= Duration::from_millis(80),
            "Expected at least ~100ms delay but got {elapsed:?}"
        );
    }

    // ── Coordinator: add reply after split ───────────────────────────

    #[tokio::test]
    async fn test_add_reply_after_connection_starts() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        let (mut read_half, mut write_half) = transport.split();

        // No reply configured yet — add it after split.
        let reply = test_packet(9000, 2, vec![0xEE]);
        coordinator.add_reply(reply.clone()).await.unwrap();

        // Now send the request.
        let request = test_packet(9000, 1, vec![0x11]);
        write_half.write_all(&request.to_bytes()).await.unwrap();

        let mut buf = vec![0u8; reply.to_bytes().len()];
        read_half.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, reply.to_bytes());
    }

    // ── Fragmented writes ────────────────────────────────────────────

    #[tokio::test]
    async fn test_fragmented_write_is_reassembled() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        let request = test_packet(10_000, 1, vec![0x01, 0x02, 0x03, 0x04]);
        let reply = test_packet(10_000, 2, vec![0xAB]);

        coordinator.add_reply(reply.clone()).await.unwrap();

        let (mut read_half, mut write_half) = transport.split();

        // Write the request in two fragments.
        let request_bytes = request.to_bytes();
        let mid = request_bytes.len() / 2;
        write_half.write_all(&request_bytes[..mid]).await.unwrap();
        // Small pause to ensure the first fragment is processed separately.
        tokio::time::sleep(Duration::from_millis(10)).await;
        write_half.write_all(&request_bytes[mid..]).await.unwrap();

        // Reply should still arrive correctly.
        let mut buf = vec![0u8; reply.to_bytes().len()];
        read_half.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, reply.to_bytes());
    }

    // ── Write half drop closes read half ─────────────────────────────

    #[tokio::test]
    async fn test_dropping_write_half_causes_read_eof() {
        let transport = MockTransport::new();
        let (mut read_half, write_half) = transport.split();

        // Drop the write half — processor exits — read channel closes.
        drop(write_half);

        // Give the processor a moment to shut down.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut buf = [0u8; 64];
        let n = read_half.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "expected EOF after write half is dropped");
    }

    // ── add_reply_bytes (raw bytes) ──────────────────────────────────

    #[tokio::test]
    async fn test_add_reply_bytes() {
        let transport = MockTransport::new();
        let coordinator = transport.coordinator();

        let reply = test_packet(11_000, 2, vec![0xCA, 0xFE]);
        coordinator
            .add_reply_bytes(11_000, 2, reply.to_bytes())
            .await
            .unwrap();

        let (mut read_half, mut write_half) = transport.split();

        let request = test_packet(11_000, 1, vec![0x00]);
        write_half.write_all(&request.to_bytes()).await.unwrap();

        let mut buf = vec![0u8; reply.to_bytes().len()];
        read_half.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, reply.to_bytes());
    }
}
