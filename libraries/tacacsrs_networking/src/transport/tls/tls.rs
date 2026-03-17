use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::transport::abstractions::Transport;

impl Transport for TlsStream<TcpStream> {
    type ReadHalf = tokio::io::ReadHalf<TlsStream<TcpStream>>;
    type WriteHalf = tokio::io::WriteHalf<TlsStream<TcpStream>>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self)
    }
}
