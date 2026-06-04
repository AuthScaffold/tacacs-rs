//! Minimal one-shot TACACS+ packet connection.
//!
//! [`DedicatedConnection`] writes packets and reads responses over one raw
//! transport without spawning background tasks or managing multiplexed sessions.
//! It is intentionally packet-level: request/reply body construction belongs in
//! flow crates layered on top of [`ClientSessionFlowIoTrait`](tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait).

use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};

use tacacsrs_messages::packet::Packet;

use crate::codec::{
    PacketReadResult, PacketReader, PacketReaderTrait, PacketWriteResult, PacketWriter,
    PacketWriterTrait,
};
use crate::transport::Transport;

use super::MultiplexedConnection;

/// A minimal TACACS+ connection that carries packet exchanges over a single
/// transport.
///
/// Unlike [`MultiplexedConnection`], this type does not spawn background tasks and
/// does not multiplex sessions. Higher-level code can wrap it in a
/// [`ClientSessionFlowIoTrait`](tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait)
/// implementation when it wants to run protocol flows over a one-shot stream.
pub(crate) struct DedicatedConnection<R, W> {
    reader_half: R,
    writer_half: W,
    reader: PacketReader,
    writer: PacketWriter,
}

impl<R, W> DedicatedConnection<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Creates a new dedicated connection by splitting a [`Transport`] into
    /// its read and write halves.
    ///
    /// If `obfuscation_key` is provided, outgoing packets are obfuscated and
    /// incoming packets are deobfuscated using the TACACS+ MD5-based XOR pad.
    pub(crate) fn new<T>(transport: T, obfuscation_key: Option<&[u8]>) -> Self
    where
        T: Transport<ReadHalf = R, WriteHalf = W>,
    {
        let key = obfuscation_key.map(<[u8]>::to_vec);
        let (reader_half, writer_half) = transport.split();
        Self {
            reader_half,
            writer_half,
            reader: PacketReader::new(key.clone()),
            writer: PacketWriter::new(key),
        }
    }

    /// Writes one TACACS+ packet to the underlying transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet cannot be written to the transport.
    pub(crate) async fn write_packet(&mut self, packet: Packet) -> anyhow::Result<()> {
        match self
            .writer
            .write_packet(&mut self.writer_half, packet)
            .await
        {
            PacketWriteResult::Success => Ok(()),
            PacketWriteResult::WriteError(error) => {
                Err(error).context("failed to write TACACS+ packet")
            }
        }
    }

    /// Reads one TACACS+ packet from the underlying transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the response header or body cannot be read or
    /// parsed.
    pub(crate) async fn read_packet(&mut self) -> anyhow::Result<Packet> {
        match self.reader.read_packet(&mut self.reader_half).await {
            PacketReadResult::Success(packet) => Ok(packet),
            PacketReadResult::HeaderReadError(error) => {
                Err(error).context("failed to read TACACS+ response header")
            }
            PacketReadResult::HeaderParseError(error) => {
                Err(error).context("failed to parse TACACS+ response header")
            }
            PacketReadResult::BodyReadError { error, .. } => {
                Err(error).context("failed to read TACACS+ response body")
            }
            PacketReadResult::BodyLengthExceeded {
                body_length,
                max_length,
                ..
            } => {
                anyhow::bail!("response body length {body_length} exceeds maximum {max_length}");
            }
            PacketReadResult::PacketCreateError { error, .. } => {
                Err(error).context("failed to create packet from response")
            }
        }
    }

    /// Consumes this dedicated connection and upgrades it to a multiplexed
    /// connection.
    ///
    /// The caller must only use this after the server has indicated support for
    /// single-connection mode. The returned connection starts with
    /// single-connect support already confirmed.
    ///
    /// ```text
    /// DedicatedConnection owns reader_half + writer_half
    ///     |
    ///     | server confirmed single-connect and session is complete
    ///     v
    /// MultiplexedConnection::new_single_connect_confirmed(key)
    ///     |
    ///     | run_with_halves(reader_half, writer_half)
    ///     v
    /// background shared read/write loops own the stream halves
    /// ```
    #[must_use]
    pub(crate) fn upgrade(self) -> Arc<MultiplexedConnection>
    where
        R: 'static,
        W: 'static,
    {
        let connection = Arc::new(MultiplexedConnection::new_single_connect_confirmed(
            self.writer.obfuscation_key(),
        ));
        connection.run_with_halves(self.reader_half, self.writer_half);
        connection
    }
}

#[cfg(test)]
mod tests;
