//! Core types for the mock transport: [`MockTransport`], [`MockReadHalf`], and [`MockWriteHalf`].
//!
//! See the [module-level documentation](super) for the overall architecture.
//! This file contains:
//!
//! - **[`MockState`]** — shared state holding pre-configured replies and captured requests.
//! - **[`MockTransport`]** — the entry point; implements [`Transport`] and can be split into
//!   a read half and a write half.
//! - **[`MockReadHalf`]** — implements [`AsyncRead`]; receives reply bytes from the write
//!   processor task via an internal channel.
//! - **[`MockWriteHalf`]** — implements [`AsyncWrite`]; forwards raw bytes to the write
//!   processor task via an internal channel.
//! - **Write processor task** — a background `tokio::spawn` task that assembles complete
//!   TACACS+ packets from raw bytes, records them as requests in [`MockState`], and
//!   dispatches any matching reply to the read half.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use tacacsrs_messages::constants::TACACS_HEADER_LENGTH;
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use crate::transport::abstractions::Transport;
use crate::transport::mock::mock_transport_coordinator::MockTransportCoordinator;

/// Configuration for a single pre-configured reply.
///
/// Stored in [`MockState::replies`] and consumed by the write processor when a
/// matching request arrives.
#[derive(Clone, Debug)]
pub(crate) struct ReplyConfig {
    /// The raw serialised TACACS+ packet bytes to send back.
    pub(crate) bytes: Vec<u8>,
    /// Optional delay before delivering the reply, useful for testing timeouts.
    pub(crate) delay: Option<Duration>,
}

/// Shared mutable state between the write processor and the [`MockTransportCoordinator`].
///
/// Protected by a `tokio::sync::Mutex` so both the async write processor task and
/// the coordinator (which may be called concurrently from test code) can access it
/// without blocking the tokio runtime.
#[derive(Debug, Default)]
pub(crate) struct MockState {
    /// Pre-configured replies, keyed by `session_id → seq_no → ReplyConfig`.
    ///
    /// Entries are **removed** (consumed) when the write processor matches them to
    /// an incoming request. This means each reply is delivered at most once.
    pub(crate) replies: HashMap<u32, HashMap<u8, ReplyConfig>>,

    /// Captured request packets, keyed by `session_id → seq_no → Packet`.
    ///
    /// Populated by the write processor. Tests read these via
    /// [`MockTransportCoordinator::get_requests_for_session`].
    pub(crate) requests: HashMap<u32, HashMap<u8, Packet>>,
}

/// A mock transport that implements [`Transport`] for integration testing.
///
/// Construct one with [`MockTransport::new()`], obtain a [`MockTransportCoordinator`]
/// via [`MockTransport::coordinator()`], then pass the transport into
/// [`TacacsConnection::run()`](crate::connection::TacacsConnection::run).
///
/// This type is [`Clone`] so you can keep a copy if needed, but [`split`](Transport::split)
/// must only be called once (enforced at runtime).
#[derive(Clone, Debug)]
pub struct MockTransport {
    /// Shared state holding replies and captured requests.
    /// Also accessed by [`MockTransportCoordinator`].
    state: Arc<Mutex<MockState>>,

    /// Sender side of the "read" channel. The write processor pushes reply bytes
    /// here so that [`MockReadHalf`] can receive them.
    read_tx: mpsc::UnboundedSender<Vec<u8>>,

    /// Receiver side of the "read" channel, wrapped in `Option` so it can be
    /// moved out exactly once during [`split`](Transport::split).
    /// The outer `Arc<Mutex<..>>` allows `MockTransport` to be `Clone`.
    read_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>>,
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
    pub fn new() -> Self {
        // This channel carries reply bytes from the write processor → MockReadHalf.
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        Self {
            state: Arc::new(Mutex::new(MockState::default())),
            read_tx,
            read_rx: Arc::new(Mutex::new(Some(read_rx))),
        }
    }

    /// Returns a [`MockTransportCoordinator`] handle for configuring and inspecting
    /// this transport.
    ///
    /// The coordinator shares the same [`MockState`] and can be used **before and
    /// during** a connection run — for example to add replies after the connection
    /// has already started processing.
    ///
    /// Multiple coordinators may be created; they all share the same underlying state.
    pub fn coordinator(&self) -> MockTransportCoordinator {
        MockTransportCoordinator {
            state: Arc::clone(&self.state),
        }
    }

    /// Spawns the **write processor** — the heart of the mock transport.
    ///
    /// This is a `tokio::spawn`-ed async task that:
    ///
    /// 1. **Receives** raw byte chunks from [`MockWriteHalf`] via `write_rx`.
    /// 2. **Accumulates** them in a local buffer (bytes may arrive in arbitrary
    ///    fragments, so we reassemble complete TACACS+ packets).
    /// 3. **Parses** each complete packet and stores it in [`MockState::requests`]
    ///    so tests can inspect what the connection sent.
    /// 4. **Looks up** a matching reply in [`MockState::replies`] for the *next*
    ///    expected sequence number (`request_seq + 1`).
    /// 5. **Sends** the reply bytes to `read_tx`, which feeds [`MockReadHalf`].
    ///    If the reply has a configured delay, a nested `tokio::spawn` sleeps first.
    ///
    /// The task exits when `write_rx` is closed (i.e. [`MockWriteHalf`] is dropped).
    ///
    /// # Why a background task?
    ///
    /// This avoids holding the [`MockState`] mutex inside a `poll_write` call.
    /// Instead, `poll_write` just pushes bytes into a channel (lock-free), and
    /// this task does the async `.lock().await` on its own, which is safe because
    /// it runs as a normal async future — not inside a `poll_*` method.
    fn spawn_write_processor(
        mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        state: Arc<Mutex<MockState>>,
        read_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            // Local buffer for reassembling complete TACACS+ packets from
            // potentially fragmented writes.
            let mut write_buffer = Vec::new();

            // Loop until the MockWriteHalf is dropped (channel closed).
            while let Some(bytes) = write_rx.recv().await {
                write_buffer.extend_from_slice(&bytes);

                // Try to drain as many complete packets as possible from the buffer.
                loop {
                    // Need at least a full header to know the packet length.
                    if write_buffer.len() < TACACS_HEADER_LENGTH {
                        break;
                    }

                    let header = Header::from_bytes(&write_buffer[..TACACS_HEADER_LENGTH])
                        .expect("mock transport: invalid TACACS+ header in request");
                    let packet_len = TACACS_HEADER_LENGTH + header.length as usize;

                    // Wait for more bytes if the full packet body hasn't arrived yet.
                    if write_buffer.len() < packet_len {
                        break;
                    }

                    // Extract and parse the complete packet.
                    let packet_bytes: Vec<u8> =
                        write_buffer.drain(..packet_len).collect();
                    let request = Packet::from_bytes(&packet_bytes)
                        .expect("mock transport: invalid TACACS+ packet in request");

                    let session_id = request.header().session_id;
                    let request_seq = request.header().seq_no;
                    // In TACACS+, the server reply has seq_no = request_seq + 1.
                    let reply_seq = request_seq.saturating_add(1);

                    // Acquire the shared state to record the request and look up the reply.
                    // This is an async lock — it cooperates with the tokio runtime and
                    // won't block other tasks while waiting.
                    let mut state = state.lock().await;

                    state
                        .requests
                        .entry(session_id)
                        .or_default()
                        .insert(request_seq, request);

                    // Remove the reply from the map (consumed — each reply fires once).
                    let reply = state
                        .replies
                        .get_mut(&session_id)
                        .and_then(|reply_map| reply_map.remove(&reply_seq));

                    // Drop the lock before doing I/O or spawning tasks to minimise
                    // the time the mutex is held.
                    drop(state);

                    if let Some(reply_config) = reply {
                        if let Some(delay) = reply_config.delay {
                            // Delayed reply: spawn a separate task that sleeps then sends.
                            let tx = read_tx.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(delay).await;
                                let _ = tx.send(reply_config.bytes);
                            });
                        } else {
                            // Immediate reply: send straight to the read half.
                            let _ = read_tx.send(reply_config.bytes);
                        }
                    }
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
    /// # Panics
    ///
    /// - If called more than once (the read receiver can only be taken once).
    /// - If called concurrently (the inner lock would already be held).
    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        // Take the read receiver out of the Option. This ensures split() is
        // only called once — a second call would find `None` and panic.
        let mut rx_guard = self
            .read_rx
            .try_lock()
            .expect("mock transport split called concurrently or receiver already locked");
        let read_rx = rx_guard
            .take()
            .expect("mock transport split called more than once");

        // Create the write channel: MockWriteHalf → write processor task.
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Spawn the background task that processes written bytes.
        // It shares `self.state` with the coordinator and pushes reply bytes
        // into `self.read_tx` which feeds the MockReadHalf.
        let processor_handle = Self::spawn_write_processor(
            write_rx,
            Arc::clone(&self.state),
            self.read_tx,
        );

        (
            MockReadHalf {
                read_rx,
                pending: Vec::new(),
            },
            MockWriteHalf {
                write_tx,
                _processor_handle: processor_handle,
            },
        )
    }
}

/// The read half of the mock transport, implementing [`AsyncRead`].
///
/// Receives reply bytes that were dispatched by the write processor task.
/// The connection's packet reader calls `poll_read` on this to receive
/// server responses.
pub struct MockReadHalf {
    /// Channel receiver for incoming reply byte chunks.
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,

    /// Leftover bytes from a previous channel message that didn't fit into the
    /// caller's buffer. Drained first on the next `poll_read` call.
    pending: Vec<u8>,
}

impl AsyncRead for MockReadHalf {
    /// Returns reply bytes to the caller.
    ///
    /// If there are leftover bytes from a previous receive (`self.pending`),
    /// those are served first. Otherwise we poll the channel for the next
    /// reply chunk. If the channel is closed (all senders dropped),
    /// returns `Ok(())` with zero bytes — signalling EOF.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If there are no pending bytes, try to receive the next chunk.
        if self.pending.is_empty() {
            match Pin::new(&mut self.read_rx).poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // Channel closed → EOF.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(bytes)) => {
                    self.pending = bytes;
                }
            }
        }

        // Copy as much as will fit into the caller's buffer.
        let to_copy = buf.remaining().min(self.pending.len());
        buf.put_slice(&self.pending[..to_copy]);
        // Keep any excess for the next call.
        self.pending.drain(..to_copy);
        Poll::Ready(Ok(()))
    }
}

/// The write half of the mock transport, implementing [`AsyncWrite`].
///
/// All data written here is forwarded to the background write processor task
/// via an unbounded channel. This means `poll_write` **never blocks or contends
/// on the shared [`MockState`] mutex** — it simply enqueues the bytes and returns.
pub struct MockWriteHalf {
    /// Channel sender to the write processor task.
    write_tx: mpsc::UnboundedSender<Vec<u8>>,

    /// Handle to the background write processor task. Stored here so the task
    /// stays alive for as long as the write half exists. When [`MockWriteHalf`]
    /// is dropped, the `write_tx` channel closes, which causes the processor
    /// task to exit on its next `recv().await`.
    _processor_handle: JoinHandle<()>,
}

impl AsyncWrite for MockWriteHalf {
    /// Forwards the written bytes to the write processor task.
    ///
    /// This is a non-blocking, lock-free operation — the bytes are simply pushed
    /// into an unbounded channel. The actual packet parsing and reply dispatch
    /// happen asynchronously in the background processor.
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mock write processor gone"))?;
        Poll::Ready(Ok(buf.len()))
    }

    /// No-op — the mock transport has no internal OS buffers to flush.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// No-op — shutdown is handled by dropping the write half, which closes the
    /// channel and causes the processor task to exit.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
