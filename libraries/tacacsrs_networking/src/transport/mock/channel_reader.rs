//! Internal [`AsyncRead`] adapter over an `mpsc::UnboundedReceiver<Vec<u8>>`.
//!
//! [`ChannelReader`] bridges tokio's channel-based message passing with the
//! byte-stream interface expected by [`AsyncRead`]. It buffers leftover bytes
//! across calls and polls the channel for new chunks when the buffer is empty.
//!
//! Used by both [`MockReadHalf`](super::mock_read_half::MockReadHalf) (to deliver reply bytes)
//! and the write processor task (to feed incoming request bytes into
//! [`PacketReader`](crate::packet_reader::PacketReader)).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

/// Internal adapter that turns an `mpsc::UnboundedReceiver<Vec<u8>>` into an
/// [`AsyncRead`] byte stream.
///
/// Each channel message is a chunk of bytes. `ChannelReader` buffers any
/// leftover bytes from the previous message and serves them on the next
/// `poll_read` before receiving a new message.
pub(super) struct ChannelReader {
    /// The underlying channel receiver.
    rx: mpsc::UnboundedReceiver<Vec<u8>>,

    /// Leftover bytes from the last received chunk that didn't fit into the
    /// caller's buffer.
    pending: Vec<u8>,

    /// Read offset into `pending`, avoiding repeated memmoves from `drain`.
    offset: usize,
}

impl ChannelReader {
    pub(super) fn new(rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            rx,
            pending: Vec::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Serve any leftover bytes from the previous message first.
        if self.offset >= self.pending.len() {
            match Pin::new(&mut self.rx).poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // Channel closed → EOF.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(bytes)) => {
                    self.pending = bytes;
                    self.offset = 0;
                }
            }
        }

        let remaining = &self.pending[self.offset..];
        let to_copy = buf.remaining().min(remaining.len());
        buf.put_slice(&remaining[..to_copy]);
        self.offset += to_copy;

        // Free the buffer once fully consumed so it doesn't linger.
        if self.offset >= self.pending.len() {
            self.pending = Vec::new();
            self.offset = 0;
        }

        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_channel_reader_eof_on_closed_channel() {
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut reader = ChannelReader::new(rx);

        // Send some data then close.
        tx.send(vec![1, 2, 3]).unwrap();
        drop(tx);

        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &[1, 2, 3]);

        // Next read should be EOF.
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_channel_reader_partial_read() {
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut reader = ChannelReader::new(rx);

        tx.send(vec![10, 20, 30, 40, 50]).unwrap();
        drop(tx);

        // Read only 2 bytes at a time.
        let mut buf = [0u8; 2];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf, &[10, 20]);

        // Remaining 3 bytes should still be available.
        let mut buf2 = [0u8; 4];
        let n = reader.read(&mut buf2).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf2[..3], &[30, 40, 50]);
    }
}
