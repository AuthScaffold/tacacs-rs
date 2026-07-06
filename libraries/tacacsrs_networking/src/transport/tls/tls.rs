use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::transport::abstractions::Transport;

impl Transport for SslStream<TcpStream> {
    type ReadHalf = tokio::io::ReadHalf<Self>;
    type WriteHalf = tokio::io::WriteHalf<Self>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self)
    }
}
