//! Transport abstraction for different stream types (TCP, TLS).
//!
//! This module provides a trait-based abstraction over different transport types,
//! allowing the connection management logic to be generic over TCP and TLS streams.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// A trait representing a bidirectional transport that can be split into
/// separate read and write halves.
///
/// This abstraction allows connection handling code to be generic over
/// different transport types (TCP, TLS, etc.) while still being able to
/// perform concurrent read and write operations.
pub trait Transport: Send + 'static {
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

/// TCP transport implementation.
impl Transport for TcpStream {
    type ReadHalf = tokio::net::tcp::OwnedReadHalf;
    type WriteHalf = tokio::net::tcp::OwnedWriteHalf;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        TcpStream::into_split(self)
    }
}

/// TLS transport implementation.
impl Transport for TlsStream<TcpStream> {
    type ReadHalf = tokio::io::ReadHalf<TlsStream<TcpStream>>;
    type WriteHalf = tokio::io::WriteHalf<TlsStream<TcpStream>>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time check that TcpStream implements Transport
    fn _assert_tcp_transport(_: impl Transport) {}
    fn _check_tcp(s: TcpStream) {
        _assert_tcp_transport(s);
    }

    // Compile-time check that TlsStream implements Transport
    fn _check_tls(s: TlsStream<TcpStream>) {
        _assert_tcp_transport(s);
    }
}
