//! Write side of the mock transport.
//!
//! Implements [`AsyncWrite`] by forwarding all written bytes to the background
//! write processor task through an unbounded channel. With this design,
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
/// through an unbounded channel. Thus, `poll_write` does not block or access the
/// shared [`MockState`](super::mock_state::MockState) mutex. It queues the bytes
/// and returns.
pub(crate) struct MockWriteHalf {
    /// Channel sender to the write processor task.
    write_tx: mpsc::UnboundedSender<Vec<u8>>,

    /// Handle to the background write processor task.
    ///
    /// The task runs independently of this handle. Dropping the handle does not
    /// stop the task. The handle permits a future join or abort operation. When
    /// [`MockWriteHalf`] is dropped, the `write_tx` channel closes. The processor
    /// task then exits at its next `recv().await`.
    _processor_handle: JoinHandle<()>,
}

impl MockWriteHalf {
    /// Creates a `MockWriteHalf` from a channel sender and a processor task.
    ///
    /// The handle does not keep the processor task alive. The task runs until it
    /// completes or the `write_tx` channel closes.
    pub(super) const fn new(
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
    /// This operation does not block or use a lock. It puts the bytes in an
    /// unbounded channel. The background processor parses packets and sends
    /// replies.
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        log::debug!("Mock write half: sending {} byte(s) to the write processor", buf.len());
        self.write_tx.send(buf.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "mock write processor stopped")
        })?;
        Poll::Ready(Ok(buf.len()))
    }

    /// Does nothing because the mock transport has no operating-system buffers.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Does nothing because dropping the write half stops the processor task.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
