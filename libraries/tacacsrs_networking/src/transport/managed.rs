//! Transport ownership that can close sockets independently of caller futures.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use super::{BoxedTransport, Transport};

struct Half<Stream> {
    stream: Option<Stream>,
    waiter: Option<Waker>,
}

struct ControlledHalf<Stream>(Mutex<Half<Stream>>);

impl<Stream> ControlledHalf<Stream> {
    fn new(stream: Stream) -> Self {
        Self(Mutex::new(Half {
            stream: Some(stream),
            waiter: None,
        }))
    }

    fn close(&self) {
        let waiter = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.stream.take();
            state.waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    fn poll<Value>(
        &self,
        context: &mut Context<'_>,
        operation: impl FnOnce(&mut Stream, &mut Context<'_>) -> Poll<io::Result<Value>>,
    ) -> Poll<io::Result<Value>> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.waiter = Some(context.waker().clone());
        match state.stream.as_mut() {
            Some(stream) => operation(stream, context),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "The TACACS+ client transport is closed",
            ))),
        }
    }
}

#[derive(Default)]
pub(crate) struct TransportActivity {
    active: AtomicUsize,
    changed: Notify,
}

impl TransportActivity {
    pub(crate) async fn wait_for_close(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }
}

pub(crate) struct TransportControl {
    reader: ControlledHalf<Box<dyn AsyncRead + Unpin + Send>>,
    writer: ControlledHalf<Box<dyn AsyncWrite + Unpin + Send>>,
    activity: Arc<TransportActivity>,
    closed: AtomicBool,
}

impl TransportControl {
    pub(crate) fn wrap(
        transport: BoxedTransport,
        activity: Arc<TransportActivity>,
    ) -> (BoxedTransport, Arc<Self>) {
        let (reader, writer) = transport.split();
        activity.active.fetch_add(1, Ordering::AcqRel);
        let control = Arc::new(Self {
            reader: ControlledHalf::new(reader),
            writer: ControlledHalf::new(writer),
            activity,
            closed: AtomicBool::new(false),
        });
        (BoxedTransport::new(ManagedTransport(control.clone())), control)
    }

    pub(crate) fn close(&self) {
        self.reader.close();
        self.writer.close();
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.activity.active.fetch_sub(1, Ordering::AcqRel);
            self.activity.changed.notify_waiters();
        }
    }
}

impl Drop for TransportControl {
    fn drop(&mut self) {
        self.close();
    }
}

struct ManagedTransport(Arc<TransportControl>);

impl Transport for ManagedTransport {
    type ReadHalf = ManagedReader;
    type WriteHalf = ManagedWriter;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        (ManagedReader(self.0.clone()), ManagedWriter(self.0))
    }
}

struct ManagedReader(Arc<TransportControl>);
struct ManagedWriter(Arc<TransportControl>);

impl AsyncRead for ManagedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.0
            .reader
            .poll(context, |stream, context| Pin::new(stream).poll_read(context, buffer))
    }
}

impl AsyncWrite for ManagedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_write(context, buffer))
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_flush(context))
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_shutdown(context))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use super::*;

    #[tokio::test]
    async fn close_releases_socket_while_read_future_is_unpolled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, peer) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let mut peer = peer.unwrap().0;
        let (transport, control) = TransportControl::wrap(
            BoxedTransport::new(client.unwrap()),
            Arc::new(TransportActivity::default()),
        );
        let (mut reader, mut writer) = transport.split();
        let mut byte = [0; 1];
        let pending = reader.read(&mut byte);
        tokio::pin!(pending);
        assert!(futures::poll!(&mut pending).is_pending());
        control.close();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), peer.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(pending.await.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            writer.write_all(b"late").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
