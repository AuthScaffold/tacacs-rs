//! Minimal one-shot TACACS+ connection.
//!
//! [`DedicatedConnection`] sends exactly one request and reads one response
//! over a raw async stream — no background tasks, no session multiplexing.
//!
//! The outgoing packet includes `TAC_PLUS_SINGLE_CONNECT_FLAG` so that the
//! server's response reveals whether it would accept session multiplexing.
//! Callers can inspect [`ExchangeResult::single_connect_supported`] to
//! decide whether future requests to this server should use a shared
//! [`TacacsConnection`] instead.

use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};

use tacacsrs_flow_abstractions::accounting::{build_accounting_packet, parse_accounting_reply};
use tacacsrs_flow_abstractions::authorization::{build_authorization_packet, parse_authorization_reply};
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::authorization::request::AuthorizationRequest;
use tacacsrs_messages::enumerations::{TacacsFlags, TacacsType};
use tacacsrs_messages::packet::{Packet, PacketTrait};

use crate::connection::TacacsConnection;
use crate::packet_reader::{PacketReadResult, PacketReader, PacketReaderTrait};
use crate::packet_writer::{PacketWriteResult, PacketWriter, PacketWriterTrait};
use crate::transport::Transport;

/// The result of a one-shot TACACS+ request-response exchange.
#[derive(Debug)]
pub struct ExchangeResult<Reply> {
    /// The parsed reply from the server.
    pub reply: Reply,
    /// Whether the server indicated support for single-connection mode
    /// by echoing `TAC_PLUS_SINGLE_CONNECT_FLAG` in its response.
    pub single_connect_supported: bool,
}

/// A minimal TACACS+ connection that carries exactly one request-response
/// exchange over a [`Transport`].
///
/// Unlike [`TacacsConnection`], this
/// type spawns no background tasks and performs no session multiplexing.
/// It writes one packet, reads one response, and reports whether the
/// server supports single-connection mode.
///
/// The struct is generic over the transport's read and write half types,
/// avoiding dynamic dispatch and extra allocations.
pub struct DedicatedConnection<R, W> {
    reader_half: R,
    writer_half: W,
    reader: PacketReader,
    writer: PacketWriter,
    session_id_fn: fn() -> u32,
}

impl<R, W> DedicatedConnection<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Creates a new dedicated connection by splitting a [`Transport`] into
    /// its read and write halves.
    ///
    /// If `obfuscation_key` is provided, outgoing packets are obfuscated
    /// and incoming packets are deobfuscated using the TACACS+ MD5-based
    /// XOR pad.
    pub fn new<T>(transport: T, obfuscation_key: Option<&[u8]>) -> Self
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
            session_id_fn: rand::random,
        }
    }

    /// Creates a new dedicated connection with a caller-supplied session ID
    /// generator.
    ///
    /// This is primarily useful in tests where a deterministic session ID
    /// is needed to pre-register replies on a mock transport.
    #[cfg(test)]
    fn new_with_session_id_fn<T>(
        transport: T,
        obfuscation_key: Option<&[u8]>,
        session_id_fn: fn() -> u32,
    ) -> Self
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
            session_id_fn,
        }
    }

    /// Sends a TACACS+ accounting request and returns the server's reply
    /// together with its single-connection negotiation result.
    ///
    /// The outgoing packet always includes `TAC_PLUS_SINGLE_CONNECT_FLAG`.
    /// If the server echoes the flag in its response, the caller knows it
    /// can switch to a shared multiplexed connection for future requests.
    /// # Errors
    /// Returns an error if the exchange fails (write, read, header mismatch, or parse failure).
    pub async fn send_accounting(
        &mut self,
        request: AccountingRequest,
        custom_flags: TacacsFlags,
    ) -> anyhow::Result<ExchangeResult<AccountingReply>> {
        let session_id: u32 = (self.session_id_fn)();
        let packet = build_accounting_packet(
            session_id,
            1,
            &request,
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG | custom_flags,
        )?;

        let response = self
            .exchange(packet)
            .await
            .context("TACACS+ accounting exchange failed")?;

        let header = response.header();
        if header.session_id != session_id
            || header.seq_no != 2
            || header.tacacs_type != TacacsType::TacPlusAccounting
        {
            anyhow::bail!(
                "unexpected TACACS+ accounting response header: session_id={:#x}, seq_no={}, type={:?}",
                header.session_id,
                header.seq_no,
                header.tacacs_type,
            );
        }

        let single_connect_supported = header
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG);

        let reply =
            parse_accounting_reply(&response).context("failed to parse accounting reply")?;

        Ok(ExchangeResult {
            reply,
            single_connect_supported,
        })
    }

    /// Sends a TACACS+ authorization request and returns the server's reply
    /// together with its single-connection negotiation result.
    ///
    /// The outgoing packet always includes `TAC_PLUS_SINGLE_CONNECT_FLAG`.
    /// If the server echoes the flag in its response, the caller knows it
    /// can switch to a shared multiplexed connection for future requests.
    /// # Errors
    /// Returns an error if the exchange fails (write, read, header mismatch, or parse failure).
    pub async fn send_authorization(
        &mut self,
        request: AuthorizationRequest,
        custom_flags: TacacsFlags,
    ) -> anyhow::Result<ExchangeResult<AuthorizationReply>> {
        let session_id: u32 = (self.session_id_fn)();
        let packet = build_authorization_packet(
            session_id,
            1,
            &request,
            TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG | custom_flags,
        )?;

        let response = self
            .exchange(packet)
            .await
            .context("TACACS+ authorization exchange failed")?;

        let header = response.header();
        if header.session_id != session_id
            || header.seq_no != 2
            || header.tacacs_type != TacacsType::TacPlusAuthorisation
        {
            anyhow::bail!(
                "unexpected TACACS+ authorization response header: session_id={:#x}, seq_no={}, type={:?}",
                header.session_id,
                header.seq_no,
                header.tacacs_type,
            );
        }

        let single_connect_supported = header
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG);

        let reply =
            parse_authorization_reply(&response).context("failed to parse authorization reply")?;

        Ok(ExchangeResult {
            reply,
            single_connect_supported,
        })
    }

    /// Writes one TACACS+ packet and reads one response.
    async fn exchange(&mut self, packet: Packet) -> anyhow::Result<Packet> {
        match self
            .writer
            .write_packet(&mut self.writer_half, packet)
            .await
        {
            PacketWriteResult::Success => {}
            PacketWriteResult::WriteError(e) => {
                return Err(e).context("failed to write TACACS+ packet");
            }
            other => anyhow::bail!("unexpected write result: {other:?}"),
        }

        match self.reader.read_packet(&mut self.reader_half).await {
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

    /// Consumes this dedicated connection and upgrades it to a multiplexed connection.
    ///
    /// This reuses the same underlying read/write halves after a successful
    /// dedicated probe has consumed its response. The returned connection starts
    /// with single-connect support already confirmed.
    #[must_use]
    pub fn upgrade(self) -> Arc<TacacsConnection>
    where
        R: 'static,
        W: 'static,
    {
        let connection =
            Arc::new(TacacsConnection::new_single_connect_confirmed(self.writer.obfuscation_key()));
        connection.run_with_halves(self.reader_half, self.writer_half);
        connection
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tacacsrs_flow_abstractions::accounting::{build_accounting_packet, parse_accounting_reply};
    use tacacsrs_messages::accounting::reply::AccountingReply;
    use tacacsrs_messages::accounting::request::AccountingRequest;
    use tacacsrs_messages::enumerations::{
        TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
        TacacsAuthenticationService, TacacsAuthenticationType, TacacsFlags,
    };
    use tacacsrs_messages::packet::PacketTrait;
    use tokio::time::timeout;

    use super::DedicatedConnection;
    use crate::SingleConnectionState;
    use crate::traits::SessionManagementTrait;
    use crate::transport::mock::MockTransport;

    const TEST_SESSION_ID: u32 = 0xDEAD_BEEF;

    fn fixed_session_id() -> u32 {
        TEST_SESSION_ID
    }

    fn test_request() -> AccountingRequest {
        AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "admin".to_string(),
            port: "tty0".to_string(),
            rem_address: "10.0.0.1".to_string(),
            args: vec!["service=shell".to_string(), "cmd=show".to_string()],
        }
    }

    fn test_reply() -> AccountingReply {
        AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "OK".to_string(),
            data: String::new(),
        }
    }

    #[tokio::test]
    async fn test_round_trip_without_obfuscation() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();

        coordinator
            .accounting_reply_for_id(TEST_SESSION_ID, 2, &test_reply())
            .with_single_connect()
            .send()
            .await
            .unwrap();

        let mut conn = DedicatedConnection::new_with_session_id_fn(mock, None, fixed_session_id);

        let result = conn
            .send_accounting(test_request(), TacacsFlags::empty())
            .await
            .unwrap();

        assert_eq!(result.reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        assert_eq!(result.reply.server_msg, "OK");
        assert!(result.single_connect_supported);

        // Verify the request was captured by the mock.
        let requests = coordinator
            .get_requests_for_session(TEST_SESSION_ID)
            .await
            .unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests.contains_key(&1));
    }

    #[tokio::test]
    async fn test_single_connect_not_supported_when_flag_absent() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();

        // Server reply does NOT include the single-connect flag.
        coordinator
            .accounting_reply_for_id(TEST_SESSION_ID, 2, &test_reply())
            .send()
            .await
            .unwrap();

        let mut conn = DedicatedConnection::new_with_session_id_fn(mock, None, fixed_session_id);

        let result = conn
            .send_accounting(test_request(), TacacsFlags::empty())
            .await
            .unwrap();

        assert!(!result.single_connect_supported);
    }

    #[tokio::test]
    async fn test_round_trip_with_obfuscation() {
        let key = b"test_secret";
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();

        // The mock transport records and replays raw bytes without
        // deobfuscation, so we must register an obfuscated reply.
        let reply = test_reply();
        coordinator
            .accounting_reply_for_id(TEST_SESSION_ID, 2, &reply)
            .with_single_connect()
            .with_obfuscation_key(key)
            .send()
            .await
            .unwrap();

        let mut conn =
            DedicatedConnection::new_with_session_id_fn(mock, Some(key), fixed_session_id);

        let result = conn
            .send_accounting(test_request(), TacacsFlags::empty())
            .await
            .unwrap();

        assert_eq!(result.reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        assert_eq!(result.reply.server_msg, "OK");
        assert!(result.single_connect_supported);

        // Verify the captured request was obfuscated (UNENCRYPTED flag cleared).
        let requests = coordinator
            .get_requests_for_session(TEST_SESSION_ID)
            .await
            .unwrap();
        let captured = &requests[&1];
        assert!(
            !captured
                .header()
                .flags
                .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG),
            "captured request should be obfuscated"
        );

        // Deobfuscate and verify the body parses.
        let deobfuscated = captured.clone().to_deobfuscated(key);
        AccountingRequest::from_bytes(deobfuscated.body())
            .expect("deobfuscated request body should parse");
    }

    #[tokio::test]
    async fn test_header_mismatch_session_id_returns_error() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();

        // Register a reply under a DIFFERENT session_id.
        let wrong_session_id = TEST_SESSION_ID.wrapping_add(1);
        coordinator
            .accounting_reply_for_id(wrong_session_id, 2, &test_reply())
            .send()
            .await
            .unwrap();

        // Also register under the real session_id with wrong seq_no=2 but
        // using the wrong session_id in the packet header, by providing raw
        // reply bytes with a mismatched session_id.
        let bad_reply = coordinator
            .accounting_reply_for_id(wrong_session_id, 2, &test_reply())
            .build()
            .unwrap();

        // Register the bad reply under the correct session_id so the mock
        // write processor will find and deliver it.
        coordinator
            .add_reply_bytes(TEST_SESSION_ID, 2, bad_reply.to_bytes())
            .await
            .unwrap();

        let mut conn = DedicatedConnection::new_with_session_id_fn(mock, None, fixed_session_id);

        let result = conn
            .send_accounting(test_request(), TacacsFlags::empty())
            .await;

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("unexpected TACACS+ accounting response header"),
            "error should mention header mismatch, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_header_mismatch_seq_no_returns_error() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();

        // Register a reply with seq_no=3 (wrong; expected 2), keyed on
        // the correct session_id + seq_no=2 so the mock delivers it.
        let bad_reply = coordinator
            .accounting_reply_for_id(TEST_SESSION_ID, 3, &test_reply())
            .build()
            .unwrap();

        coordinator
            .add_reply_bytes(TEST_SESSION_ID, 2, bad_reply.to_bytes())
            .await
            .unwrap();

        let mut conn = DedicatedConnection::new_with_session_id_fn(mock, None, fixed_session_id);

        let result = conn
            .send_accounting(test_request(), TacacsFlags::empty())
            .await;

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("unexpected TACACS+ accounting response header"),
            "error should mention header mismatch, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_custom_flags_are_set_on_outgoing_packet() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();

        coordinator
            .accounting_reply_for_id(TEST_SESSION_ID, 2, &test_reply())
            .send()
            .await
            .unwrap();

        let mut conn = DedicatedConnection::new_with_session_id_fn(mock, None, fixed_session_id);

        let custom = TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1 | TacacsFlags::TAC_PLUS_CUSTOM_FLAG_2;
        let result = conn.send_accounting(test_request(), custom).await.unwrap();

        assert_eq!(result.reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);

        // Verify the captured request has both custom flags and the
        // single-connect flag set.
        let requests = coordinator
            .get_requests_for_session(TEST_SESSION_ID)
            .await
            .unwrap();
        let captured = &requests[&1];
        let flags = captured.header().flags;
        assert!(flags.contains(TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1));
        assert!(flags.contains(TacacsFlags::TAC_PLUS_CUSTOM_FLAG_2));
        assert!(flags.contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
    }

    #[tokio::test]
    async fn test_upgrade_reuses_stream_for_multiplexed_session() {
        let mock = MockTransport::new();
        let coordinator = mock.coordinator();

        coordinator
            .accounting_reply_for_id(TEST_SESSION_ID, 2, &test_reply())
            .with_single_connect()
            .send()
            .await
            .unwrap();

        let mut dedicated =
            DedicatedConnection::new_with_session_id_fn(mock, None, fixed_session_id);
        let probe = dedicated
            .send_accounting(test_request(), TacacsFlags::empty())
            .await
            .unwrap();
        assert!(probe.single_connect_supported);

        let connection = dedicated.upgrade();
        assert_eq!(connection.single_connection_state().await, SingleConnectionState::Supported);

        let session = connection.create_session().await.unwrap();
        coordinator
            .accounting_reply(&session, 2, &test_reply())
            .with_single_connect()
            .send()
            .await
            .unwrap();

        let seq_no = session.next_sequence_number().await;
        let packet = build_accounting_packet(
            session.session_id(),
            seq_no,
            &test_request(),
            TacacsFlags::empty(),
        )
        .unwrap();
        session.duplex_channel.sender.send(packet).await.unwrap();

        let mut receiver = session.duplex_channel.receiver.write().await;
        let response = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("upgraded multiplexed session should receive a reply")
            .expect("response channel should remain open");
        drop(receiver);

        let reply = parse_accounting_reply(&response).unwrap();
        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        session.complete().await;

        let requests = coordinator
            .get_requests_for_session(session.session_id())
            .await
            .unwrap();
        assert!(requests.contains_key(&1));
    }
}
