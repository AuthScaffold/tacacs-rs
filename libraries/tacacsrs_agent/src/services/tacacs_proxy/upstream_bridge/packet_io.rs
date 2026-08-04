//! TACACS+ packet IO helpers for the raw proxy.

use std::time::Duration;

use anyhow::{Context, bail};
use tacacsrs_messages::constants::{TACACS_HEADER_LENGTH, TACACS_MAX_BODY_LENGTH};
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_networking::{PacketWriteResult, PacketWriter};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

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

pub(super) async fn read_downstream_packet<Stream>(
    stream: &mut Stream,
    timeout: Duration,
    obfuscation_key: Option<&[u8]>,
) -> Result<DownstreamPacket, ProxyConnectionError>
where
    Stream: AsyncRead + Unpin + Send,
{
    tokio::time::timeout(timeout, read_downstream_packet_inner(stream, obfuscation_key))
        .await
        .map_err(|_| {
            ProxyConnectionError::Downstream(anyhow::anyhow!(
                "Timed out waiting for downstream TACACS+ packet after {timeout:?}"
            ))
        })?
        .map_err(ProxyConnectionError::Downstream)
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
            anyhow::Error::new(error).context("Failed to write TACACS+ proxy reply downstream"),
        )),
    }
}

async fn read_downstream_packet_inner<Stream>(
    stream: &mut Stream,
    obfuscation_key: Option<&[u8]>,
) -> anyhow::Result<DownstreamPacket>
where
    Stream: AsyncRead + Unpin + Send,
{
    let mut header_buffer = [0_u8; TACACS_HEADER_LENGTH];
    stream
        .read_exact(&mut header_buffer)
        .await
        .context("Failed to read TACACS+ proxy header")?;

    let header =
        Header::from_bytes(&header_buffer).context("Failed to parse TACACS+ proxy header")?;
    let session_id = header.session_id;
    if header.length > TACACS_MAX_BODY_LENGTH {
        bail!(
            "TACACS+ proxy packet for session {session_id:#x} declared body length {}, exceeding maximum {}",
            header.length,
            TACACS_MAX_BODY_LENGTH,
        );
    }

    let reply_obfuscation = if header
        .flags
        .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG)
    {
        DownstreamObfuscation::Unobfuscated
    } else {
        DownstreamObfuscation::Obfuscated
    };

    let mut body_buffer = vec![0_u8; header.length as usize];
    stream.read_exact(&mut body_buffer).await.with_context(|| {
        format!("Failed to read TACACS+ proxy body for session {session_id:#x}")
    })?;

    let mut packet = Packet::new(header, body_buffer).with_context(|| {
        format!("Failed to create TACACS+ proxy packet for session {session_id:#x}")
    })?;

    log::debug!(
        "Read TACACS+ proxy downstream packet: session_id={:#x}, seq_no={}, type={}, flags={:?}, body_length={}, obfuscated={}",
        packet.header().session_id,
        packet.header().seq_no,
        packet.header().tacacs_type,
        packet.header().flags,
        packet.body().len(),
        reply_obfuscation == DownstreamObfuscation::Obfuscated,
    );

    if reply_obfuscation == DownstreamObfuscation::Obfuscated {
        if let Some(key) = obfuscation_key {
            log::debug!(
                "Deobfuscating TACACS+ proxy downstream packet body for session {:#x}",
                packet.header().session_id,
            );
            packet = packet.to_deobfuscated(key);
        }
    }

    Ok(DownstreamPacket {
        packet,
        reply_obfuscation,
    })
}
