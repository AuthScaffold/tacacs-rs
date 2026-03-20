use tokio::net::TcpStream;

use crate::transport::abstractions::Transport;

impl Transport for TcpStream {
    type ReadHalf = tokio::net::tcp::OwnedReadHalf;
    type WriteHalf = tokio::net::tcp::OwnedWriteHalf;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        Self::into_split(self)
    }
}
