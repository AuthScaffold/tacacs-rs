//! TACACS+ packet I/O helpers for the raw proxy.

use std::time::Duration;

use anyhow::{Context, bail};
use tacacsrs_messages::constants::{TACACS_HEADER_LENGTH, TACACS_MAX_BODY_LENGTH};
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_networking::{PacketWriteResult, PacketWriter};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::Instant;

use super::error::ProxyConnectionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DownstreamObfuscation {
    Unobfuscated,
    Obfuscated,
}

pub(super) struct DownstreamPacket {
    pub(super) packet: Packet,
    pub(super) reply_obfuscation: DownstreamObfuscation,
}

/// Cancellation-safe packet reader for one downstream proxy client.
///
/// The connection loop polls [`next_packet`](Self::next_packet) inside
/// `select!`. Every partially read byte is stored in this struct rather than in
/// the returned future, so a losing `select!` branch cannot discard bytes and
/// desynchronise the TACACS+ frame boundary.
pub(super) struct DownstreamReader<Stream> {
    stream: Stream,
    obfuscation_key: Option<Vec<u8>>,
    timeout: Duration,
    deadline: Option<Instant>,
    header_bytes: [u8; TACACS_HEADER_LENGTH],
    header_filled: usize,
    header: Option<Header>,
    body: Vec<u8>,
    body_filled: usize,
}

impl<Stream> DownstreamReader<Stream>
where
    Stream: AsyncRead + Unpin + Send,
{
    pub(super) const fn new(
        stream: Stream,
        timeout: Duration,
        obfuscation_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            stream,
            obfuscation_key,
            timeout,
            deadline: None,
            header_bytes: [0_u8; TACACS_HEADER_LENGTH],
            header_filled: 0,
            header: None,
            body: Vec::new(),
            body_filled: 0,
        }
    }

    /// Reads the next complete downstream packet.
    ///
    /// The read deadline covers one whole packet, so a client cannot hold the
    /// connection open by sending a frame one byte at a time.
    pub(super) async fn next_packet(&mut self) -> Result<DownstreamPacket, ProxyConnectionError> {
        let deadline = *self
            .deadline
            .get_or_insert_with(|| Instant::now() + self.timeout);
        let timeout = self.timeout;

        match tokio::time::timeout_at(deadline, self.read_frame()).await {
            Ok(Ok(packet)) => {
                self.deadline = None;
                Ok(packet)
            }
            Ok(Err(error)) => Err(ProxyConnectionError::Downstream(error)),
            Err(_) => Err(ProxyConnectionError::Downstream(anyhow::anyhow!(
                "No downstream TACACS+ packet arrived within {timeout:?}"
            ))),
        }
    }

    async fn read_frame(&mut self) -> anyhow::Result<DownstreamPacket> {
        while self.header_filled < TACACS_HEADER_LENGTH {
            let Self {
                stream,
                header_bytes,
                header_filled,
                ..
            } = &mut *self;
            let read = stream
                .read(&mut header_bytes[*header_filled..])
                .await
                .context("Failed to read TACACS+ proxy header")?;
            if read == 0 {
                bail!("Failed to read TACACS+ proxy header: early eof");
            }
            *header_filled += read;
        }

        if self.header.is_none() {
            let header = Header::from_bytes(&self.header_bytes)
                .context("Failed to parse TACACS+ proxy header")?;
            if header.length > TACACS_MAX_BODY_LENGTH {
                bail!(
                    "TACACS+ proxy packet for session {:#x} declares body length {}, which exceeds the maximum of {}",
                    header.session_id,
                    header.length,
                    TACACS_MAX_BODY_LENGTH,
                );
            }
            self.body = vec![0_u8; header.length as usize];
            self.body_filled = 0;
            self.header = Some(header);
        }

        let body_length = self.body.len();
        while self.body_filled < body_length {
            let Self {
                stream,
                body,
                body_filled,
                ..
            } = &mut *self;
            let read = stream
                .read(&mut body[*body_filled..])
                .await
                .context("Failed to read a TACACS+ proxy body")?;
            if read == 0 {
                bail!("Failed to read a TACACS+ proxy body: early eof");
            }
            *body_filled += read;
        }

        let header = self.header.take().expect("the header is parsed above");
        let body = std::mem::take(&mut self.body);
        self.header_filled = 0;
        self.body_filled = 0;

        let session_id = header.session_id;
        let reply_obfuscation = if header
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG)
        {
            DownstreamObfuscation::Unobfuscated
        } else {
            DownstreamObfuscation::Obfuscated
        };

        let mut packet = Packet::new(header, body).with_context(|| {
            format!("Failed to create TACACS+ proxy packet for session {session_id:#x}")
        })?;

        log::debug!(
            "Read a downstream TACACS+ proxy packet: session_id={:#x}, seq_no={}, type={}, flags={:?}, body_length={}, obfuscated={}",
            packet.header().session_id,
            packet.header().seq_no,
            packet.header().tacacs_type,
            packet.header().flags,
            packet.body().len(),
            reply_obfuscation == DownstreamObfuscation::Obfuscated,
        );

        if reply_obfuscation == DownstreamObfuscation::Obfuscated {
            if let Some(key) = &self.obfuscation_key {
                log::debug!(
                    "Deobfuscating a downstream TACACS+ proxy packet body for session {session_id:#x}"
                );
                packet = packet.to_deobfuscated(key);
            }
        }

        Ok(DownstreamPacket {
            packet,
            reply_obfuscation,
        })
    }
}

#[cfg(test)]
pub(super) async fn read_downstream_packet<Stream>(
    stream: &mut Stream,
    timeout: Duration,
    obfuscation_key: Option<&[u8]>,
) -> Result<DownstreamPacket, ProxyConnectionError>
where
    Stream: AsyncRead + Unpin + Send,
{
    DownstreamReader::new(stream, timeout, obfuscation_key.map(<[u8]>::to_vec))
        .next_packet()
        .await
}

pub(super) async fn write_downstream_packet<Stream>(
    writer: &PacketWriter,
    stream: &mut Stream,
    packet: Packet,
    obfuscation: DownstreamObfuscation,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncWrite + Unpin + Send,
{
    let result = match obfuscation {
        DownstreamObfuscation::Obfuscated => writer.write_packet(stream, packet).await,
        DownstreamObfuscation::Unobfuscated => {
            PacketWriter::new(None).write_packet(stream, packet).await
        }
    };

    match result {
        PacketWriteResult::Success => Ok(()),
        PacketWriteResult::WriteError(error) => Err(ProxyConnectionError::Downstream(
            anyhow::Error::new(error).context("Failed to write a TACACS+ proxy reply downstream"),
        )),
    }
}
