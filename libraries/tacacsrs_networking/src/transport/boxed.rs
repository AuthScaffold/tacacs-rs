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
pub(crate) struct BoxedTransport {
    transport: Box<dyn ErasedTransport>,
    revocation_evidence_lifetime: Option<super::tls::RevocationEvidenceLifetime>,
    counters: Option<crate::ServerCounters>,
    connection_record: Option<std::sync::Arc<crate::statistics::ConnectionRecord>>,
    tls_details: Option<crate::TlsDetails>,
}

impl BoxedTransport {
    /// Wraps a concrete transport in a type-erased wrapper.
    pub(crate) fn new<T: Transport>(transport: T) -> Self {
        let counters = transport.counters();
        Self {
            transport: Box::new(transport),
            revocation_evidence_lifetime: None,
            counters,
            connection_record: None,
            tls_details: None,
        }
    }

    pub(crate) fn with_counters(mut self, counters: crate::ServerCounters) -> Self {
        self.connection_record =
            Some(std::sync::Arc::new(crate::statistics::ConnectionRecord::new(counters.clone())));
        self.counters = Some(counters);
        self
    }

    pub(crate) fn connection_record(
        &self,
    ) -> Option<std::sync::Arc<crate::statistics::ConnectionRecord>> {
        self.connection_record.clone()
    }

    pub(crate) fn with_tls_details(mut self, details: crate::TlsDetails) -> Self {
        self.tls_details = Some(details);
        self
    }

    pub(crate) fn tls_details(&self) -> Option<crate::TlsDetails> {
        self.tls_details.clone()
    }

    pub(crate) fn with_revocation_evidence_lifetime(
        mut self,
        lifetime: super::tls::RevocationEvidenceLifetime,
    ) -> Self {
        self.revocation_evidence_lifetime = Some(lifetime);
        self
    }

    pub(crate) const fn revocation_evidence_lifetime(
        &self,
    ) -> Option<super::tls::RevocationEvidenceLifetime> {
        self.revocation_evidence_lifetime
    }
}

impl Transport for BoxedTransport {
    fn counters(&self) -> Option<crate::ServerCounters> {
        self.counters.clone()
    }
    type ReadHalf = Box<dyn AsyncRead + Unpin + Send>;
    type WriteHalf = Box<dyn AsyncWrite + Unpin + Send>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        self.transport.split_boxed()
    }
}
