//! TACACS+ packet I/O helpers for the raw proxy.

use std::future::Future;
use std::pin::pin;
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;

use anyhow::{Context, bail};
use tacacsrs_messages::constants::{TACACS_HEADER_LENGTH, TACACS_MAX_BODY_LENGTH};
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_networking::{PacketWriteResult, PacketWriter};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader};
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
    stream: BufReader<Stream>,
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
    pub(super) fn new(stream: Stream, timeout: Duration, obfuscation_key: Option<Vec<u8>>) -> Self {
        Self {
            // Buffering lets one syscall deliver a whole small TACACS+ packet.
            stream: BufReader::new(stream),
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
        // Buffered bytes often already hold a whole packet. Completing here
        // avoids arming and disarming a timer for every request.
        if let Some(result) = self.poll_read_frame_once() {
            self.deadline = None;
            return result.map_err(ProxyConnectionError::Downstream);
        }

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

    /// Polls one read attempt without registering a real waker.
    ///
    /// Partial progress stays in `self`, so discarding the future is safe.
    fn poll_read_frame_once(&mut self) -> Option<anyhow::Result<DownstreamPacket>> {
        let mut context = TaskContext::from_waker(Waker::noop());
        match pin!(self.read_frame()).poll(&mut context) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
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

/// Encodes several replies into `buffer` and sends them with one write.
///
/// Each reply keeps its own obfuscation setting, so mixed batches stay correct.
pub(super) async fn write_downstream_batch<Stream, Replies>(
    writer: &PacketWriter,
    stream: &mut Stream,
    replies: Replies,
    buffer: &mut Vec<u8>,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncWrite + Unpin + Send,
    Replies: IntoIterator<Item = (Packet, DownstreamObfuscation)>,
{
    let unobfuscated = PacketWriter::new(None);

    buffer.clear();
    for (packet, obfuscation) in replies {
        match obfuscation {
            DownstreamObfuscation::Obfuscated => writer.encode_into(packet, buffer),
            DownstreamObfuscation::Unobfuscated => unobfuscated.encode_into(packet, buffer),
        }
    }

    match PacketWriter::write_encoded(stream, buffer).await {
        PacketWriteResult::Success => Ok(()),
        PacketWriteResult::WriteError(error) => Err(ProxyConnectionError::Downstream(
            anyhow::Error::new(error).context("Failed to write a TACACS+ proxy reply downstream"),
        )),
    }
}
