//! Type-erased transport.
//!
//! [`BoxedTransport`] wraps any [`Transport`] in a trait object. Thus, callers
//! can return one type for different connection types, such as TCP and TLS.

use tokio::io::{AsyncRead, AsyncWrite};

use super::abstractions::Transport;

/// Object-safe helper that stores any [`Transport`] in a `Box`.
trait ErasedTransport: Send + 'static {
    fn split_boxed(
        self: Box<Self>,
    ) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>);
}

impl<T: Transport> ErasedTransport for T {
    fn split_boxed(
        self: Box<Self>,
    ) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) {
        let (r, w) = (*self).split();
        (Box::new(r), Box::new(w))
    }
}

/// A type-erased [`Transport`].
///
/// Use [`BoxedTransport::new`] with a concrete [`Transport`] implementation,
/// such as `TcpStream` or `TlsStream<TcpStream>`.
pub(crate) struct BoxedTransport(
    Box<dyn ErasedTransport>,
    Option<super::tls::CertificateLifetime>,
    Option<crate::ServerCounters>,
    Option<std::sync::Arc<crate::statistics::ConnectionRecord>>,
);

impl BoxedTransport {
    /// Wraps a concrete transport in a type-erased wrapper.
    pub(crate) fn new<T: Transport>(transport: T) -> Self {
        let counters = transport.counters();
        Self(Box::new(transport), None, counters, None)
    }

    pub(crate) fn with_counters(mut self, counters: crate::ServerCounters) -> Self {
        self.3 =
            Some(std::sync::Arc::new(crate::statistics::ConnectionRecord::new(counters.clone())));
        self.2 = Some(counters);
        self
    }

    pub(crate) fn connection_record(
        &self,
    ) -> Option<std::sync::Arc<crate::statistics::ConnectionRecord>> {
        self.3.clone()
    }

    pub(crate) fn with_certificate_lifetime(
        mut self,
        lifetime: super::tls::CertificateLifetime,
    ) -> Self {
        self.1 = Some(lifetime);
        self
    }

    pub(crate) const fn certificate_lifetime(&self) -> Option<super::tls::CertificateLifetime> {
        self.1
    }
}

impl Transport for BoxedTransport {
    fn counters(&self) -> Option<crate::ServerCounters> {
        self.2.clone()
    }
    type ReadHalf = Box<dyn AsyncRead + Unpin + Send>;
    type WriteHalf = Box<dyn AsyncWrite + Unpin + Send>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        self.0.split_boxed()
    }
}
