//! Minimal one-shot TACACS+ connection.
//!
//! [`DedicatedConnection`] sends exactly one request and reads one response
//! over a raw async stream — no background tasks, no session multiplexing.
//!
//! The outgoing packet includes `TAC_PLUS_SINGLE_CONNECT_FLAG` so that the
//! server's response reveals whether it would accept session multiplexing.
//! Callers can inspect [`ExchangeResult::single_connect_supported`] to
//! decide whether future requests to this server should use a shared
//! [`TacacsConnection`](crate::connection::TacacsConnection) instead.

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

use crate::packet_reader::{PacketReadResult, PacketReader, PacketReaderTrait};
use crate::packet_writer::{PacketWriteResult, PacketWriter, PacketWriterTrait};

/// The result of a one-shot TACACS+ accounting exchange.
#[derive(Debug)]
pub struct ExchangeResult {
    /// The accounting reply from the server.
    pub reply: AccountingReply,
    /// Whether the server indicated support for single-connection mode
    /// by echoing `TAC_PLUS_SINGLE_CONNECT_FLAG` in its response.
    pub single_connect_supported: bool,
}

/// A minimal TACACS+ connection that carries exactly one request-response
/// exchange over a raw async stream.
///
/// Unlike [`TacacsConnection`](crate::connection::TacacsConnection), this
/// type spawns no background tasks and performs no session multiplexing.
/// It writes one packet, reads one response, and reports whether the
/// server supports single-connection mode.
pub struct DedicatedConnection<S> {
    stream: S,
    reader: PacketReader,
    writer: PacketWriter,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> DedicatedConnection<S> {
    /// Creates a new dedicated connection over `stream`.
    ///
    /// If `obfuscation_key` is provided, outgoing packets are obfuscated
    /// and incoming packets are deobfuscated using the TACACS+ MD5-based
    /// XOR pad.
    #[must_use]
    pub fn new(stream: S, obfuscation_key: Option<&[u8]>) -> Self {
        let key = obfuscation_key.map(<[u8]>::to_vec);
        Self {
            stream,
            reader: PacketReader::new(key.clone()),
            writer: PacketWriter::new(key),
        }
    }

    /// Sends a TACACS+ accounting request and returns the server's reply
    /// together with its single-connection negotiation result.
    ///
    /// The outgoing packet always includes `TAC_PLUS_SINGLE_CONNECT_FLAG`.
    /// If the server echoes the flag in its response, the caller knows it
    /// can switch to a shared multiplexed connection for future requests.
    pub async fn send_accounting(
        &mut self,
        request: AccountingRequest,
        custom_flags: TacacsFlags,
    ) -> anyhow::Result<ExchangeResult> {
        let session_id: u32 = rand::random();
        let body = request.to_bytes();
        let flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG
            | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG
            | custom_flags;

        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: 1,
                flags,
                session_id,
                length: body.len() as u32,
            },
            body,
        )?;

        let response = self
            .exchange(packet)
            .await
            .context("TACACS+ accounting exchange failed")?;

        let single_connect_supported = response
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG);

        let reply = AccountingReply::from_bytes(response.body())
            .context("failed to parse accounting reply")?;

        Ok(ExchangeResult {
            reply,
            single_connect_supported,
        })
    }

    /// Writes one TACACS+ packet and reads one response.
    async fn exchange(&mut self, packet: Packet) -> anyhow::Result<Packet> {
        match self.writer.write_packet(&mut self.stream, packet).await {
            PacketWriteResult::Success => {}
            PacketWriteResult::WriteError(e) => {
                return Err(e).context("failed to write TACACS+ packet");
            }
            other => anyhow::bail!("unexpected write result: {other:?}"),
        }

        match self.reader.read_packet(&mut self.stream).await {
            PacketReadResult::Success(packet) => Ok(packet),
            PacketReadResult::HeaderReadError(e) => {
                Err(e).context("failed to read TACACS+ response header")
            }
            PacketReadResult::HeaderParseError(e) => {
                Err(e).context("failed to parse TACACS+ response header")
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
}
