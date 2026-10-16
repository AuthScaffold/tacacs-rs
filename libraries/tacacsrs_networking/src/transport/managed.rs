//! Transport ownership that can close sockets independently of caller futures.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
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
    lifetime: Option<super::tls::CertificateLifetime>,
    expiry: OnceLock<Arc<crate::connection::task::DriverTask>>,
    counters: Option<crate::ServerCounters>,
    graceful: AtomicBool,
    record: Option<Arc<crate::statistics::ConnectionRecord>>,
}

impl TransportControl {
    pub(crate) fn wrap(
        transport: BoxedTransport,
        activity: Arc<TransportActivity>,
    ) -> (BoxedTransport, Arc<Self>) {
        let lifetime = transport.certificate_lifetime();
        let counters = transport.counters();
        let record = transport.connection_record();
        let (reader, writer) = transport.split();
        activity.active.fetch_add(1, Ordering::AcqRel);
        let control = Arc::new(Self {
            reader: ControlledHalf::new(reader),
            writer: ControlledHalf::new(writer),
            activity,
            closed: AtomicBool::new(false),
            lifetime,
            expiry: OnceLock::new(),
            counters,
            graceful: AtomicBool::new(false),
            record,
        });
        if let Some(lifetime) = lifetime {
            let weak = Arc::downgrade(&control);
            let task = crate::connection::task::DriverTask::spawn(async move {
                loop {
                    let clock_check =
                        tokio::time::Instant::now() + std::time::Duration::from_secs(1);
                    tokio::time::sleep_until(lifetime.deadline.expires_at().min(clock_check)).await;
                    let Some(control) = weak.upgrade() else {
                        break;
                    };
                    if control.closed.load(Ordering::Acquire) || lifetime.check().is_err() {
                        control.close();
                        break;
                    }
                }
                Ok(())
            });
            let _ = control.expiry.set(Arc::new(task));
        }
        (BoxedTransport::new(ManagedTransport(control.clone())), control)
    }

    pub(crate) fn expiry_task(&self) -> Option<Arc<crate::connection::task::DriverTask>> {
        self.expiry.get().cloned()
    }

    fn check_expiry(&self) -> io::Result<()> {
        if self
            .lifetime
            .is_some_and(|lifetime| lifetime.check().is_err())
        {
            self.close();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TLS certificate validity expired",
            ));
        }
        Ok(())
    }

    pub(crate) fn close(&self) {
        self.finish(false);
    }

    fn finish(&self, graceful: bool) {
        if let Some(task) = self.expiry.get() {
            task.abort();
        }
        self.reader.close();
        self.writer.close();
        if !self.closed.swap(true, Ordering::AcqRel) {
            if let Some(record) = &self.record {
                record.close(graceful);
            }
            self.activity.active.fetch_sub(1, Ordering::AcqRel);
            self.activity.changed.notify_waiters();
        }
    }
}

impl Drop for TransportControl {
    fn drop(&mut self) {
        self.finish(self.graceful.load(Ordering::Acquire));
    }
}

struct ManagedTransport(Arc<TransportControl>);

impl Transport for ManagedTransport {
    fn counters(&self) -> Option<crate::ServerCounters> {
        self.0.counters.clone()
    }
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
        if let Err(error) = self.0.check_expiry() {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        let has_capacity = buffer.remaining() != 0;
        let result = self
            .0
            .reader
            .poll(context, |stream, context| Pin::new(stream).poll_read(context, buffer));
        match &result {
            Poll::Ready(Ok(())) if has_capacity && buffer.filled().len() == before => {
                self.0.graceful.store(true, Ordering::Release);
            }
            Poll::Ready(Err(_)) => self.0.close(),
            _ => {}
        }
        result
    }
}

impl AsyncWrite for ManagedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.0.check_expiry() {
            return Poll::Ready(Err(error));
        }
        let result = self
            .0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_write(context, buffer));
        if matches!(&result, Poll::Ready(Err(_))) {
            self.0.close();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.0.check_expiry() {
            return Poll::Ready(Err(error));
        }
        let result = self
            .0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_flush(context));
        if matches!(&result, Poll::Ready(Err(_))) {
            self.0.close();
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.0.check_expiry() {
            return Poll::Ready(Err(error));
        }
        let result = self
            .0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_shutdown(context));
        match &result {
            Poll::Ready(Ok(())) => self.0.graceful.store(true, Ordering::Release),
            Poll::Ready(Err(_)) => self.0.close(),
            Poll::Pending => {}
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use super::*;

    async fn expiring_transport() -> (BoxedTransport, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, peer) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let certificate = openssl::x509::X509::from_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lde/containers/config/certificates/client.crt"
        )))
        .unwrap();
        let lifetime = crate::transport::tls::CertificateLifetime {
            validity: crate::transport::tls::CertificateValidity::from_certificate(&certificate)
                .unwrap(),
            deadline: crate::RequestDeadline::after(std::time::Duration::from_secs(1)).unwrap(),
        };
        (BoxedTransport::new(client.unwrap()).with_certificate_lifetime(lifetime), peer.unwrap().0)
    }

    #[tokio::test(start_paused = true)]
    async fn expired_io_closes_both_halves_even_when_the_timer_is_cancelled() {
        let (transport, mut peer) = expiring_transport().await;
        let activity = Arc::new(TransportActivity::default());
        let (transport, control) = TransportControl::wrap(transport, activity.clone());
        let task = control.expiry_task().unwrap();
        task.abort();
        task.join_until(crate::RequestDeadline::after(std::time::Duration::ZERO).unwrap())
            .await
            .unwrap();
        let (mut reader, mut writer) = transport.split();
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            writer.write_all(b"late").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            reader.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        control.close();
        assert_eq!(activity.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_task_does_not_retain_transport_owners() {
        let (transport, mut peer) = expiring_transport().await;
        let activity = Arc::new(TransportActivity::default());
        let (transport, control) = TransportControl::wrap(transport, activity.clone());
        let task = control.expiry_task().unwrap();
        let weak = Arc::downgrade(&control);
        drop(control);
        drop(transport);
        task.join_until(crate::RequestDeadline::after(std::time::Duration::ZERO).unwrap())
            .await
            .unwrap();
        assert!(weak.upgrade().is_none());
        assert!(task.is_finished());
        assert_eq!(activity.active.load(Ordering::Acquire), 0);
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }

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
