//! [`MockWriteHalf`] — the write side of the mock transport.
//!
//! Implements [`AsyncWrite`] by forwarding all written bytes to the background
//! write processor task via an unbounded channel. This design ensures that
//! `poll_write` never contends on the shared
//! [`MockState`](super::mock_state::MockState) mutex.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The write half of the mock transport, implementing [`AsyncWrite`].
///
/// All data written here is forwarded to the background write processor task
/// via an unbounded channel. This means `poll_write` **never blocks or contends
/// on the shared [`MockState`](super::mock_state::MockState) mutex** — it simply
/// enqueues the bytes and returns.
pub struct MockWriteHalf {
    /// Channel sender to the write processor task.
    write_tx: mpsc::UnboundedSender<Vec<u8>>,

    /// Handle to the background write processor task. Stored here so the task
    /// stays alive for as long as the write half exists. When [`MockWriteHalf`]
    /// is dropped, the `write_tx` channel closes, which causes the processor
    /// task to exit on its next `recv().await`.
    _processor_handle: JoinHandle<()>,
}

impl MockWriteHalf {
    /// Creates a new `MockWriteHalf` from the given channel sender and
    /// processor task handle.
    pub(super) fn new(
        write_tx: mpsc::UnboundedSender<Vec<u8>>,
        processor_handle: JoinHandle<()>,
    ) -> Self {
        Self {
            write_tx,
            _processor_handle: processor_handle,
        }
    }
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
