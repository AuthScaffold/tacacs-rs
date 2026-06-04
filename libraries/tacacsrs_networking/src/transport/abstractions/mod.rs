//! Shared transport abstractions.
//!
//! This module contains traits and shared behavior used by all transport
//! implementations.

use tokio::io::{AsyncRead, AsyncWrite};

/// A trait representing a bidirectional transport that can be split into
/// separate read and write halves.
///
/// This abstraction allows connection handling code to be generic over
/// different transport types (TCP, TLS, etc.) while still being able to
/// perform concurrent read and write operations.
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
    use tokio_rustls::client::TlsStream;

    // Compile-time check that TcpStream implements Transport
    #[allow(dead_code)]
    fn assert_transport(_: impl Transport) {}

    #[allow(dead_code)]
    fn check_tcp(s: TcpStream) {
        assert_transport(s);
    }

    // Compile-time check that TlsStream implements Transport
    #[allow(dead_code)]
    fn check_tls(s: TlsStream<TcpStream>) {
        assert_transport(s);
    }

    // Compile-time check that MockTransport implements Transport
    #[allow(dead_code)]
    fn check_mock(s: crate::transport::mock::MockTransport) {
        assert_transport(s);
    }

    // Compile-time check that OpenSSL-backed SslStream implements Transport
    #[cfg(feature = "psk")]
    #[allow(dead_code)]
    fn check_openssl(s: tokio_openssl::SslStream<TcpStream>) {
        assert_transport(s);
    }
}
