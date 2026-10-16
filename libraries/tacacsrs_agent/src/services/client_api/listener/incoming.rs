//! Bounds accepted IPC transports before Tonic creates connection tasks.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
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
    registry: Arc<Mutex<TransportRegistry>>,
}

#[derive(Default)]
struct TransportRegistry {
    closed: bool,
    streams: Vec<Weak<Mutex<StreamState>>>,
}

struct StreamState {
    stream: Option<UnixStream>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

pub(super) struct TransportGuard(Arc<Mutex<TransportRegistry>>);

impl Drop for TransportGuard {
    fn drop(&mut self) {
        let streams = {
            let mut registry = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry.closed = true;
            std::mem::take(&mut registry.streams)
        };
        for stream in streams.into_iter().filter_map(|stream| stream.upgrade()) {
            let (read, write) = {
                let mut state = stream
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.stream.take();
                (state.read_waker.take(), state.write_waker.take())
            };
            if let Some(waker) = read {
                waker.wake();
            }
            if let Some(waker) = write {
                waker.wake();
            }
        }
    }
}

impl LimitedIncoming {
    pub(super) fn new(listener: UnixListener, limit: usize, lifetime: Duration) -> Self {
        Self {
            listener: Arc::new(listener),
            capacity: Arc::new(Semaphore::new(limit)),
            lifetime,
            accept: None,
            registry: Arc::default(),
        }
    }

    pub(super) fn close_guard(&self) -> TransportGuard {
        TransportGuard(self.registry.clone())
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
            let registry = this.registry.clone();
            Box::pin(async move {
                let permit = capacity.acquire_owned().await.map_err(io::Error::other)?;
                let (stream, _) = listener.accept().await?;
                let expires = Instant::now() + lifetime;
                let connect_info = stream.connect_info();
                let stream = Arc::new(Mutex::new(StreamState {
                    stream: Some(stream),
                    read_waker: None,
                    write_waker: None,
                }));
                {
                    let mut registry = registry
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if registry.closed {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "The IPC listener is closed",
                        ));
                    }
                    registry.streams.retain(|stream| stream.strong_count() > 0);
                    registry.streams.push(Arc::downgrade(&stream));
                }
                Ok(LimitedStream {
                    stream,
                    connect_info,
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
    stream: Arc<Mutex<StreamState>>,
    connect_info: <UnixStream as Connected>::ConnectInfo,
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
        let mut state = this
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.read_waker = Some(context.waker().clone());
        let stream = state.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "The IPC listener is closed")
        })?;
        Pin::new(stream).poll_read(context, buffer)
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
        let mut state = this
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.write_waker = Some(context.waker().clone());
        let stream = state.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "The IPC listener is closed")
        })?;
        Pin::new(stream).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        check_expiry(&mut this.write_expiry, context)?;
        let mut state = this
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.write_waker = Some(context.waker().clone());
        let stream = state.stream.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "The IPC listener is closed")
        })?;
        Pin::new(stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match state.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_shutdown(context),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl Connected for LimitedStream {
    type ConnectInfo = <UnixStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.connect_info.clone()
    }
}
