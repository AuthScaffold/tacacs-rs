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
    evidence_lifetime: Option<super::tls::RevocationEvidenceLifetime>,
    evidence_expiry: OnceLock<Arc<crate::connection::task::DriverTask>>,
    counters: Option<crate::ServerCounters>,
    graceful: AtomicBool,
    record: Option<Arc<crate::statistics::ConnectionRecord>>,
}

impl TransportControl {
    pub(crate) fn wrap(
        transport: BoxedTransport,
        activity: Arc<TransportActivity>,
    ) -> (BoxedTransport, Arc<Self>) {
        let evidence_lifetime = transport.revocation_evidence_lifetime();
        let counters = transport.counters();
        let record = transport.connection_record();
        let (reader, writer) = transport.split();
        activity.active.fetch_add(1, Ordering::AcqRel);
        let control = Arc::new(Self {
            reader: ControlledHalf::new(reader),
            writer: ControlledHalf::new(writer),
            activity,
            closed: AtomicBool::new(false),
            evidence_lifetime,
            evidence_expiry: OnceLock::new(),
            counters,
            graceful: AtomicBool::new(false),
            record,
        });
        if let Some(lifetime) = evidence_lifetime {
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
                        if let Some(counters) = &control.counters {
                            counters.disconnect_reason(crate::DisconnectReason::CredentialExpired);
                        }
                        control.close();
                        break;
                    }
                }
                Ok(())
            });
            let _ = control.evidence_expiry.set(Arc::new(task));
        }
        (BoxedTransport::new(ManagedTransport(control.clone())), control)
    }

    pub(crate) fn evidence_expiry_task(&self) -> Option<Arc<crate::connection::task::DriverTask>> {
        self.evidence_expiry.get().cloned()
    }

    fn check_evidence_expiry(&self) -> io::Result<()> {
        if self
            .evidence_lifetime
            .is_some_and(|lifetime| lifetime.check().is_err())
        {
            if let Some(counters) = &self.counters {
                counters.disconnect_reason(crate::DisconnectReason::CredentialExpired);
            }
            self.close();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TLS revocation evidence expired",
            ));
        }
        Ok(())
    }

    pub(crate) fn close(&self) {
        self.finish(false);
    }

    fn finish(&self, graceful: bool) {
        if let Some(task) = self.evidence_expiry.get() {
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
        if let Err(error) = self.0.check_evidence_expiry() {
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
                if let Some(counters) = &self.0.counters {
                    counters.io_error(&io::Error::from(io::ErrorKind::UnexpectedEof), false);
                }
                self.0.graceful.store(true, Ordering::Release);
            }
            Poll::Ready(Err(error)) => {
                if let Some(counters) = &self.0.counters {
                    counters.io_error(error, false);
                }
                self.0.close();
            }
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
        if let Err(error) = self.0.check_evidence_expiry() {
            return Poll::Ready(Err(error));
        }
        let result = self
            .0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_write(context, buffer));
        if let Poll::Ready(Err(error)) = &result {
            if let Some(counters) = &self.0.counters {
                counters.io_error(error, true);
            }
            self.0.close();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.0.check_evidence_expiry() {
            return Poll::Ready(Err(error));
        }
        let result = self
            .0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_flush(context));
        if let Poll::Ready(Err(error)) = &result {
            if let Some(counters) = &self.0.counters {
                counters.io_error(error, true);
            }
            self.0.close();
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.0.check_evidence_expiry() {
            return Poll::Ready(Err(error));
        }
        let result = self
            .0
            .writer
            .poll(context, |stream, context| Pin::new(stream).poll_shutdown(context));
        match &result {
            Poll::Ready(Ok(())) => self.0.graceful.store(true, Ordering::Release),
            Poll::Ready(Err(error)) => {
                if let Some(counters) = &self.0.counters {
                    counters.io_error(error, true);
                }
                self.0.close();
            }
            Poll::Pending => {}
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use super::*;

    async fn bounded_native_io<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(3), future)
            .await
            .expect("native test I/O must finish")
    }

    async fn counted_tcp_transport(
    ) -> (BoxedTransport, Arc<TransportControl>, tokio::net::TcpStream, crate::ServerCounters) {
        let listener = bounded_native_io(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .await
            .unwrap();
        let (client, peer) = bounded_native_io(async {
            tokio::join!(
                tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            )
        })
        .await;
        let owner = crate::ServerCounters::default();
        let counters = owner.for_connection(None, None);
        let transport = BoxedTransport::new(client.unwrap()).with_counters(counters);
        let (transport, control) =
            TransportControl::wrap(transport, Arc::new(TransportActivity::default()));
        (transport, control, peer.unwrap().0, owner)
    }

    async fn expiring_transport() -> (BoxedTransport, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, peer) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let now = std::time::SystemTime::now();
        let lifetime = crate::transport::tls::RevocationEvidenceLifetime {
            validity: crate::transport::tls::RevocationEvidenceValidity::from_bounds(
                now - std::time::Duration::from_secs(1),
                now + std::time::Duration::from_secs(60),
            )
            .unwrap(),
            deadline: crate::RequestDeadline::after(std::time::Duration::from_secs(1)).unwrap(),
        };
        (
            BoxedTransport::new(client.unwrap()).with_revocation_evidence_lifetime(lifetime),
            peer.unwrap().0,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn expired_evidence_closes_both_halves_even_when_the_timer_is_cancelled() {
        let (transport, mut peer) = expiring_transport().await;
        let activity = Arc::new(TransportActivity::default());
        let (transport, control) = TransportControl::wrap(transport, activity.clone());
        let task = control.evidence_expiry_task().unwrap();
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
    async fn evidence_expiry_task_does_not_retain_transport_owners() {
        let (transport, mut peer) = expiring_transport().await;
        let activity = Arc::new(TransportActivity::default());
        let (transport, control) = TransportControl::wrap(transport, activity.clone());
        let task = control.evidence_expiry_task().unwrap();
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

    #[tokio::test]
    async fn peer_eof_and_higher_layer_report_count_one_read_error() {
        let (transport, control, mut peer, owner) = counted_tcp_transport().await;
        let (mut reader, writer) = transport.split();
        bounded_native_io(peer.shutdown()).await.unwrap();
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), reader.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(bounded_native_io(reader.read(&mut byte)).await.unwrap(), 0);
        control
            .counters
            .as_ref()
            .unwrap()
            .io_error(&io::Error::from(io::ErrorKind::UnexpectedEof), false);
        let diagnostics = owner.snapshot().diagnostics;
        assert_eq!(diagnostics.read_errors, 1);
        assert_eq!(diagnostics.write_errors, 0);
        assert_eq!(diagnostics.peer_disconnects, 0);
        drop(reader);
        drop(writer);
        control.close();
        let diagnostics = owner.snapshot().diagnostics;
        assert_eq!(diagnostics.read_errors, 1);
        assert_eq!(diagnostics.resets, 1);
        assert_eq!(diagnostics.peer_disconnects, 1);
        assert_eq!(diagnostics.malformed_disconnects, 0);
    }

    #[tokio::test]
    async fn zero_capacity_read_does_not_record_eof() {
        let (transport, control, mut peer, owner) = counted_tcp_transport().await;
        let (mut reader, writer) = transport.split();
        bounded_native_io(peer.shutdown()).await.unwrap();
        let mut empty = [];
        let mut empty_buffer = ReadBuf::new(&mut empty);
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            std::future::poll_fn(|context| {
                Pin::new(&mut reader).poll_read(context, &mut empty_buffer)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let diagnostics = owner.snapshot().diagnostics;
        assert_eq!(diagnostics.read_errors, 0);
        assert_eq!(diagnostics.peer_disconnects, 0);
        assert!(diagnostics.last_disconnect_reason.is_none());
        drop(reader);
        drop(writer);
        control.close();
        assert_eq!(owner.snapshot().diagnostics.read_errors, 0);
    }

    #[tokio::test]
    async fn valid_reads_and_writes_do_not_change_error_counters() {
        let (transport, control, mut peer, owner) = counted_tcp_transport().await;
        let (mut reader, mut writer) = transport.split();
        bounded_native_io(peer.write_all(b"x")).await.unwrap();
        let mut byte = [0; 1];
        bounded_native_io(reader.read_exact(&mut byte))
            .await
            .unwrap();
        assert_eq!(&byte, b"x");
        bounded_native_io(writer.write_all(b"y")).await.unwrap();
        bounded_native_io(peer.read_exact(&mut byte)).await.unwrap();
        assert_eq!(&byte, b"y");
        let snapshot = owner.snapshot();
        assert_eq!(snapshot.messages_received, 0);
        assert_eq!(snapshot.messages_sent, 0);
        assert_eq!(snapshot.diagnostics.read_errors, 0);
        assert_eq!(snapshot.diagnostics.write_errors, 0);
        control.close();
    }

    #[tokio::test]
    async fn native_tls_close_notify_counts_one_tls_read_error() {
        use openssl::pkey::PKey;
        use openssl::ssl::{SslContext, SslMethod, SslVersion, Ssl};
        use openssl::x509::X509;

        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../lde/containers/config/certificates");
        let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
        context
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        context
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        context
            .set_certificate(
                X509::from_pem(&std::fs::read(fixtures.join("server.crt")).unwrap())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
        context
            .set_private_key(
                PKey::private_key_from_pem(&std::fs::read(fixtures.join("server.key")).unwrap())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
        context.check_private_key().unwrap();
        let context = context.build();
        let authority = X509::from_pem(&std::fs::read(fixtures.join("ca.crt")).unwrap())
            .unwrap()
            .to_der()
            .unwrap();
        let listener = bounded_native_io(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .await
            .unwrap();
        let config = crate::TlsClientConfig::prepare(
            "localhost",
            None,
            crate::CertificateTrust::Certificates {
                authorities: &[&authority],
                end_entities: &[],
            },
            None,
            crate::CertificateVerification::Required,
        )
        .unwrap();
        let endpoint = crate::PreparedEndpoint::new(
            listener.local_addr().unwrap().try_into().unwrap(),
            crate::PreparedTransport::Tls(config),
            false,
            None,
            crate::ConnectOptions::default(),
        );
        let owner = endpoint.counters();
        let server_handshake_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let client_handshake_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let server_barrier = server_handshake_barrier.clone();
        let client_barrier = client_handshake_barrier.clone();
        let (close_sender, close_receiver) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (tcp, _) =
                tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut stream =
                tokio_openssl::SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), Pin::new(&mut stream).accept())
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), server_barrier.wait())
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), client_barrier.wait())
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), close_receiver)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.shutdown())
                .await
                .unwrap()
                .unwrap();
        });
        let transport = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            crate::establish::establish_stream(&endpoint),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), server_handshake_barrier.wait())
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), client_handshake_barrier.wait())
            .await
            .unwrap();
        let (transport, control) =
            TransportControl::wrap(transport, Arc::new(TransportActivity::default()));
        let (mut reader, writer) = transport.split();
        let mut byte = [0; 1];
        let length = {
            let read = reader.read(&mut byte);
            tokio::pin!(read);
            assert!(futures::poll!(&mut read).is_pending());
            close_sender.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut read)
                .await
                .unwrap()
                .unwrap()
        };
        assert_eq!(length, 0);
        let diagnostics = owner.snapshot().diagnostics;
        assert_eq!(diagnostics.read_errors, 1);
        assert_eq!(diagnostics.tls_read_errors, 1);
        assert_eq!(diagnostics.write_errors, 0);
        assert_eq!(diagnostics.tls_write_errors, 0);
        drop(reader);
        drop(writer);
        control.close();
        tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap();
        let diagnostics = owner.snapshot().diagnostics;
        assert_eq!(diagnostics.read_errors, 1);
        assert_eq!(diagnostics.tls_read_errors, 1);
        assert_eq!(diagnostics.resets, 1);
        assert_eq!(diagnostics.peer_disconnects, 1);
        assert_eq!(diagnostics.malformed_disconnects, 0);
    }

    #[tokio::test]
    async fn existing_disconnect_reason_remains_authoritative_at_eof() {
        let (transport, control, mut peer, owner) = counted_tcp_transport().await;
        control
            .counters
            .as_ref()
            .unwrap()
            .disconnect_reason(crate::DisconnectReason::MalformedPacket);
        let (mut reader, writer) = transport.split();
        bounded_native_io(peer.shutdown()).await.unwrap();
        assert_eq!(bounded_native_io(reader.read(&mut [0; 1])).await.unwrap(), 0);
        assert_eq!(owner.snapshot().diagnostics.read_errors, 0);
        drop(reader);
        drop(writer);
        control.close();
        let diagnostics = owner.snapshot().diagnostics;
        assert_eq!(diagnostics.resets, 1);
        assert_eq!(diagnostics.peer_disconnects, 0);
        assert_eq!(diagnostics.malformed_disconnects, 1);
    }
}
