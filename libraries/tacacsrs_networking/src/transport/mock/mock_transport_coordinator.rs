//! The [`MockTransportCoordinator`] — the test-facing control handle for the mock transport.
//!
//! See the [module-level documentation](super) for the overall architecture.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

use crate::session::Session;
use super::mock_state::{MockState, ReplyConfig};

/// Builder for registering accounting reply packets on a [`MockTransportCoordinator`].
///
/// Created via [`MockTransportCoordinator::accounting_reply`] or
/// [`MockTransportCoordinator::accounting_reply_for_id`]. Call [`send`](Self::send)
/// to finalize construction and register the reply.
///
/// # Defaults
///
/// | Field | Default |
/// |-------|---------|
/// | `flags` | [`TAC_PLUS_UNENCRYPTED_FLAG`](TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG) |
/// | `delay` | `None` (immediate) |
/// | `obfuscation_key` | `None` (plaintext) |
pub struct MockAccountingReplyBuilder<'a> {
    coordinator: &'a MockTransportCoordinator,
    session_id: u32,
    seq_no: u8,
    reply: &'a AccountingReply,
    flags: TacacsFlags,
    delay: Option<Duration>,
    obfuscation_key: Option<&'a [u8]>,
}

impl<'a> MockAccountingReplyBuilder<'a> {
    /// Overrides the default flags on the reply packet header.
    ///
    /// By default the builder uses [`TAC_PLUS_UNENCRYPTED_FLAG`](TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG).
    /// Calling this **replaces** the flags entirely.
    #[must_use]
    pub fn with_flags(mut self, flags: TacacsFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Adds [`TAC_PLUS_SINGLE_CONNECT_FLAG`](TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
    /// to the reply packet header flags.
    #[must_use]
    pub fn with_single_connect(mut self) -> Self {
        self.flags |= TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
        self
    }

    /// Delivers the reply after `delay` instead of immediately.
    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Obfuscates the reply packet before registering it.
    ///
    /// The mock transport replays raw bytes without deobfuscation, so
    /// an obfuscated reply must be pre-obfuscated to match what a real
    /// TACACS+ server would send.
    #[must_use]
    pub fn with_obfuscation_key(mut self, key: &'a [u8]) -> Self {
        self.obfuscation_key = Some(key);
        self
    }

    /// Builds the accounting reply packet and registers it on the coordinator.
    /// # Errors
    /// Returns an error if the reply packet cannot be constructed.
    pub async fn send(self) -> anyhow::Result<()> {
        let coordinator = self.coordinator;
        let delay = self.delay;
        let packet = self.build()?;

        if let Some(delay) = delay {
            coordinator.add_reply_with_delay(packet, delay).await
        } else {
            coordinator.add_reply(packet).await
        }
    }

    /// Builds the accounting reply packet and returns it without registering.
    ///
    /// This is useful when a test needs to register the packet under a
    /// different session ID or sequence number than the one in the header
    /// (e.g. to test header-mismatch error handling).
    /// # Errors
    /// Returns an error if the reply packet cannot be constructed.
    pub fn build(self) -> anyhow::Result<Packet> {
        let data = self.reply.to_bytes();
        let mut packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: self.seq_no,
                flags: self.flags,
                session_id: self.session_id,
                length: data.len() as u32,
            },
            data,
        )?;

        if let Some(key) = self.obfuscation_key {
            packet = packet.to_obfuscated(key);
        }

        Ok(packet)
    }
}

/// Control handle for configuring and inspecting a [`super::MockTransport`].
///
/// Obtained via [`MockTransport::coordinator()`](super::MockTransport::coordinator).
/// This handle shares the same `MockState` as the transport, connected through an
/// `Arc<Mutex<..>>`. It can be held independently from the transport instance that
/// is consumed by `TacacsConnection::run()`, so tests do not need to clone the
/// transport itself.
///
/// # Concurrency
///
/// All methods acquire the shared async mutex, so it is safe to call these
/// **while the connection is running** (e.g. to add a reply mid-conversation).
/// The mutex is held only for the duration of the `HashMap` insert/lookup.
#[derive(Clone, Debug)]
pub struct MockTransportCoordinator {
    /// Shared state with the write processor task.
    pub(crate) state: Arc<Mutex<MockState>>,
}

impl MockTransportCoordinator {
    /// Registers a reply packet that will be sent when the write processor
    /// receives a request for the same `session_id` with `seq_no - 1`.
    ///
    /// The session ID and sequence number are extracted from the packet header.
    /// # Errors
    /// Returns an error if the packet header cannot be read.
    pub async fn add_reply(&self, reply: Packet) -> anyhow::Result<()> {
        let session_id = reply.header().session_id;
        let seq_no = reply.header().seq_no;
        log::info!("mock coordinator: registering reply for session {session_id} seq_no {seq_no}");
        self.add_reply_bytes(session_id, seq_no, reply.to_bytes())
            .await
    }

    /// Registers raw pre-serialised reply bytes for a given session and sequence number.
    ///
    /// This is the low-level building block used by the other `add_reply*` methods.
    /// Use this when you need full control over the byte representation (e.g. to
    /// test malformed packets).
    ///
    /// # Arguments
    ///
    /// * `session_id` — the TACACS+ session ID the reply belongs to.
    /// * `seq_no` — the sequence number of the reply (must be `request_seq + 1`).
    /// * `reply_bytes` — the complete serialised packet bytes.
    /// # Errors
    /// This method is infallible but returns `Result` for API consistency.
    pub async fn add_reply_bytes(
        &self,
        session_id: u32,
        seq_no: u8,
        reply_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        log::info!(
            "mock coordinator: registering raw reply bytes ({} bytes) for session {session_id} seq_no {seq_no}",
            reply_bytes.len()
        );
        let mut state = self.state.lock().await;
        let reply_list = state.replies.entry(session_id).or_default();
        reply_list.insert(
            seq_no,
            ReplyConfig {
                bytes: reply_bytes,
                delay: None,
            },
        );
        Ok(())
    }

    /// Registers a reply packet that will be delivered after a specified delay.
    ///
    /// Useful for testing timeout behaviour — the write processor spawns a task
    /// that sleeps for `delay` before sending the reply bytes.
    /// # Errors
    /// This method is infallible but returns `Result` for API consistency.
    pub async fn add_reply_with_delay(&self, reply: Packet, delay: Duration) -> anyhow::Result<()> {
        log::info!(
            "mock coordinator: registering delayed reply ({delay:?}) for session {} seq_no {}",
            reply.header().session_id,
            reply.header().seq_no
        );
        let mut state = self.state.lock().await;
        let reply_list = state.replies.entry(reply.header().session_id).or_default();
        reply_list.insert(
            reply.header().seq_no,
            ReplyConfig {
                bytes: reply.to_bytes(),
                delay: Some(delay),
            },
        );
        Ok(())
    }

    /// Creates a [`MockAccountingReplyBuilder`] for registering an accounting
    /// reply associated with the given session.
    ///
    /// # Arguments
    ///
    /// * `session` — provides the session ID for the reply.
    /// * `reply_sequence_number` — the sequence number for the reply.
    /// * `reply` — the accounting reply body.
    pub fn accounting_reply<'a>(
        &'a self,
        session: &Session,
        reply_sequence_number: u8,
        reply: &'a AccountingReply,
    ) -> MockAccountingReplyBuilder<'a> {
        MockAccountingReplyBuilder {
            coordinator: self,
            session_id: session.session_id(),
            seq_no: reply_sequence_number,
            reply,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            delay: None,
            obfuscation_key: None,
        }
    }

    /// Creates a [`MockAccountingReplyBuilder`] for registering an accounting
    /// reply for a known `session_id`.
    ///
    /// This is the counterpart of [`accounting_reply`](Self::accounting_reply)
    /// for callers that do not have a [`Session`] reference — e.g. when
    /// testing [`DedicatedConnection`](crate::DedicatedConnection) with a
    /// predetermined session ID.
    #[must_use]
    pub fn accounting_reply_for_id<'a>(
        &'a self,
        session_id: u32,
        reply_sequence_number: u8,
        reply: &'a AccountingReply,
    ) -> MockAccountingReplyBuilder<'a> {
        MockAccountingReplyBuilder {
            coordinator: self,
            session_id,
            seq_no: reply_sequence_number,
            reply,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            delay: None,
            obfuscation_key: None,
        }
    }

    /// Returns all request packets captured for the given `session_id`.
    ///
    /// The returned map is keyed by sequence number. These are the packets that
    /// the connection actually wrote through the transport.
    ///
    /// **Note:** The mock transport does **not** deobfuscate packets — it
    /// operates like a network capture (pcap). If the connection under test
    /// uses an obfuscation key, the packet bodies returned here will still
    /// be obfuscated. Call [`Packet::to_deobfuscated`] with the appropriate
    /// key if you need to inspect cleartext content.
    ///
    /// # Errors
    ///
    /// Returns an error if no requests have been recorded for `session_id`.
    pub async fn get_requests_for_session(
        &self,
        session_id: u32,
    ) -> anyhow::Result<HashMap<u8, Packet>> {
        let state = self.state.lock().await;
        let result = state.requests.get(&session_id).cloned();
        let count = result.as_ref().map_or(0, std::collections::HashMap::len);
        log::debug!(
            "mock coordinator: get_requests_for_session({session_id}) → {count} request(s)"
        );
        result.ok_or_else(|| {
            anyhow::anyhow!("No requests recorded for session {session_id} (session not seen)")
        })
    }

    /// Returns **unconsumed** reply packets still configured for the given `session_id`.
    ///
    /// Replies that have already been matched and sent by the write processor
    /// are removed from the map and will **not** appear here. This is useful
    /// for verifying that all expected replies were actually consumed.
    ///
    /// # Errors
    ///
    /// Returns an error if no replies are configured for `session_id`.
    pub async fn get_replies_for_session(
        &self,
        session_id: u32,
    ) -> anyhow::Result<HashMap<u8, Packet>> {
        let state = self.state.lock().await;
        let configured = state.replies.get(&session_id).ok_or_else(|| {
            anyhow::anyhow!("No replies configured for session {session_id} (session not found)")
        })?;
        log::debug!(
            "mock coordinator: get_replies_for_session({session_id}) → {} unconsumed reply(ies)",
            configured.len()
        );

        configured
            .iter()
            .map(|(seq, config)| Packet::from_bytes(&config.bytes).map(|p| (*seq, p)))
            .collect()
    }
}
