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
pub(crate) struct BoxedTransport(Box<dyn ErasedTransport>);

impl BoxedTransport {
    /// Wraps a concrete transport in a type-erased wrapper.
    pub(crate) fn new<T: Transport>(transport: T) -> Self {
        Self(Box::new(transport))
    }
}

impl Transport for BoxedTransport {
    type ReadHalf = Box<dyn AsyncRead + Unpin + Send>;
    type WriteHalf = Box<dyn AsyncWrite + Unpin + Send>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        self.0.split_boxed()
    }
}
