//! Bounds accepted IPC transports before Tonic creates connection tasks.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};
use tokio_stream::Stream;
use tonic::transport::server::Connected;

type AcceptFuture = Pin<Box<dyn Future<Output = io::Result<LimitedStream>> + Send>>;

pub(super) struct LimitedIncoming {
    listener: Arc<UnixListener>,
    capacity: Arc<Semaphore>,
    lifetime: Duration,
    accept: Option<AcceptFuture>,
}

impl LimitedIncoming {
    pub(super) fn new(listener: UnixListener, limit: usize, lifetime: Duration) -> Self {
        Self {
            listener: Arc::new(listener),
            capacity: Arc::new(Semaphore::new(limit)),
            lifetime,
            accept: None,
        }
    }
}

impl Stream for LimitedIncoming {
    type Item = io::Result<LimitedStream>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let accept = this.accept.get_or_insert_with(|| {
            let listener = Arc::clone(&this.listener);
            let capacity = Arc::clone(&this.capacity);
            let lifetime = this.lifetime;
            Box::pin(async move {
                let permit = capacity.acquire_owned().await.map_err(io::Error::other)?;
                let (stream, _) = listener.accept().await?;
                let expires = Instant::now() + lifetime;
                Ok(LimitedStream {
                    stream,
                    _permit: permit,
                    read_expiry: Box::pin(tokio::time::sleep_until(expires)),
                    write_expiry: Box::pin(tokio::time::sleep_until(expires)),
                })
            })
        });
        match accept.as_mut().poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.accept = None;
                Poll::Ready(Some(result))
            }
        }
    }
}

pub(super) struct LimitedStream {
    stream: UnixStream,
    _permit: OwnedSemaphorePermit,
    read_expiry: Pin<Box<Sleep>>,
    write_expiry: Pin<Box<Sleep>>,
}

fn check_expiry(timer: &mut Pin<Box<Sleep>>, context: &mut Context<'_>) -> io::Result<()> {
    if timer.as_mut().poll(context).is_ready() {
        Err(io::Error::new(io::ErrorKind::TimedOut, "The IPC connection lifetime expired"))
    } else {
        Ok(())
    }
}

impl AsyncRead for LimitedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        check_expiry(&mut this.read_expiry, context)?;
        Pin::new(&mut this.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for LimitedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        check_expiry(&mut this.write_expiry, context)?;
        Pin::new(&mut this.stream).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        check_expiry(&mut this.write_expiry, context)?;
        Pin::new(&mut this.stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

impl Connected for LimitedStream {
    type ConnectInfo = <UnixStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}
