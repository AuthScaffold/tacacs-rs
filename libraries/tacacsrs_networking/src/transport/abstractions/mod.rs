//! Shared transport abstractions.
//!
//! This module contains traits and shared behavior used by all transport
//! implementations.

use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional transport that can be split into
/// separate read and write halves.
///
/// Connection code uses this trait for TCP, TLS, and other transports. The code
/// can read and write concurrently.
pub(crate) trait Transport: Send + 'static {
    /// The read half type after splitting the transport.
    type ReadHalf: AsyncRead + Unpin + Send + 'static;
    /// The write half type after splitting the transport.
    type WriteHalf: AsyncWrite + Unpin + Send + 'static;

    /// Splits the transport into separate read and write halves.
    ///
    /// This consumes the transport and returns two independent halves that
    /// can be used concurrently for reading and writing.
    fn split(self) -> (Self::ReadHalf, Self::WriteHalf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;
    use tokio_openssl::SslStream;

    // Make sure that TcpStream implements Transport.
    #[allow(dead_code)]
    fn assert_transport(_: impl Transport) {}

    #[allow(dead_code)]
    fn check_tcp(s: TcpStream) {
        assert_transport(s);
    }

    // Make sure that SslStream implements Transport.
    #[allow(dead_code)]
    fn check_tls(s: SslStream<TcpStream>) {
        assert_transport(s);
    }

    // Make sure that MockTransport implements Transport.
    #[allow(dead_code)]
    fn check_mock(s: crate::transport::mock::MockTransport) {
        assert_transport(s);
    }
}
