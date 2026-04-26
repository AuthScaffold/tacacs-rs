//! [`MockReadHalf`] — the read side of the mock transport.
//!
//! Implements [`AsyncRead`] by delegating to a [`ChannelReader`]
//! that receives reply bytes dispatched by the background write processor task.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

use super::channel_reader::ChannelReader;

/// The read half of the mock transport, implementing [`AsyncRead`].
///
/// Receives reply bytes that were dispatched by the write processor task.
/// The connection's packet reader calls `poll_read` on this to receive
/// server responses.
///
/// Internally delegates to a [`ChannelReader`].
pub struct MockReadHalf {
    /// The channel-backed reader that does the actual buffering and reading.
    inner: ChannelReader,
}

impl MockReadHalf {
    /// Creates a new `MockReadHalf` backed by the given channel receiver.
    pub(super) const fn new(rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            inner: ChannelReader::new(rx),
        }
    }
}

impl AsyncRead for MockReadHalf {
    /// Returns reply bytes to the caller.
    ///
    /// Delegates to [`ChannelReader`], which buffers leftover bytes across
    /// calls and polls the internal channel for new chunks when needed.
    /// Returns EOF (`Ok(())` with zero bytes) when the channel is closed.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
