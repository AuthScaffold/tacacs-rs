//! TACACS+ packet IO helpers for the raw proxy.

use std::time::Duration;

use anyhow::bail;
use tacacsrs_config::TacacsPlusServer;
use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_networking::{
    PacketReadResult, PacketReader, PacketReaderTrait, PacketWriteResult, PacketWriter,
    PacketWriterTrait,
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::error::ProxyConnectionError;

pub(super) async fn read_downstream_packet<Stream>(
    reader: &PacketReader,
    stream: &mut Stream,
    timeout: Duration,
) -> Result<Packet, ProxyConnectionError>
where
    Stream: AsyncRead + Unpin + Send,
{
    let result = tokio::time::timeout(timeout, reader.read_packet(stream))
        .await
        .map_err(|_| {
            ProxyConnectionError::Downstream(anyhow::anyhow!(
                "Timed out waiting for downstream TACACS+ packet after {timeout:?}"
            ))
        })?;

    packet_read_result_to_result(result).map_err(ProxyConnectionError::Downstream)
}

pub(super) async fn read_upstream_packet<Session>(
    upstream_session: &Session,
    timeout: Duration,
) -> Result<Packet, ProxyConnectionError>
where
    Session: ClientSessionFlowIoTrait + Sync + ?Sized,
{
    tokio::time::timeout(timeout, upstream_session.receive_packet())
        .await
        .map_err(|_| {
            ProxyConnectionError::Upstream(anyhow::anyhow!(
                "Timed out waiting for upstream TACACS+ reply after {timeout:?}"
            ))
        })?
        .map_err(|error| {
            ProxyConnectionError::Upstream(
                error.context("Failed to receive upstream TACACS+ reply"),
            )
        })
}

pub(super) async fn write_downstream_packet<Stream>(
    writer: &PacketWriter,
    stream: &mut Stream,
    packet: Packet,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncWrite + Unpin + Send,
{
    match writer.write_packet(stream, packet).await {
        PacketWriteResult::Success => Ok(()),
        PacketWriteResult::WriteError(error) => Err(ProxyConnectionError::Downstream(
            anyhow::Error::new(error).context("Failed to write TACACS+ proxy reply downstream"),
        )),
    }
}

pub(super) fn validate_downstream_obfuscation(
    packet: &Packet,
    server: &TacacsPlusServer,
) -> Result<(), ProxyConnectionError> {
    if server.shared_secret.is_some()
        || packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG)
    {
        return Ok(());
    }

    Err(ProxyConnectionError::Downstream(anyhow::anyhow!(
        "Downstream TACACS+ packet for session {:#x} is obfuscated, but selected upstream server {} has no shared secret",
        packet.header().session_id,
        server.name,
    )))
}

fn packet_read_result_to_result(result: PacketReadResult) -> anyhow::Result<Packet> {
    match result {
        PacketReadResult::Success(packet) => Ok(packet),
        PacketReadResult::HeaderReadError(error) => {
            Err(anyhow::Error::new(error).context("Failed to read TACACS+ proxy header"))
        }
        PacketReadResult::HeaderParseError(error) => {
            Err(error.context("Failed to parse TACACS+ proxy header"))
        }
        PacketReadResult::BodyLengthExceeded {
            session_id,
            body_length,
            max_length,
        } => bail!(
            "TACACS+ proxy packet for session {session_id:#x} declared body length {body_length}, exceeding maximum {max_length}"
        ),
        PacketReadResult::BodyReadError { session_id, error } => Err(anyhow::Error::new(error)
            .context(format!("Failed to read TACACS+ proxy body for session {session_id:#x}"))),
        PacketReadResult::PacketCreateError { session_id, error } => Err(error.context(format!(
            "Failed to create TACACS+ proxy packet for session {session_id:#x}"
        ))),
    }
}
