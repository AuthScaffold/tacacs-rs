//! Test control handle for the mock transport.
//!
//! See the [module-level documentation](super) for the overall architecture.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

use crate::session::SharedSession;
use super::mock_state::{MockState, ReplyConfig};

/// Builder for registering accounting reply packets on a [`MockTransportCoordinator`].
///
/// Create this builder through [`MockTransportCoordinator::accounting_reply`] or
/// [`MockTransportCoordinator::accounting_reply_for_id`]. Call [`send`](Self::send)
/// to finish construction and register the reply.
///
/// # Defaults
///
/// | Field | Default |
/// |-------|---------|
/// | `flags` | [`TAC_PLUS_UNENCRYPTED_FLAG`](TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG) |
/// | `delay` | `None` (immediate) |
/// | `obfuscation_key` | `None` (plaintext) |
pub(crate) struct MockAccountingReplyBuilder<'a> {
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
    /// The default is
    /// [`TAC_PLUS_UNENCRYPTED_FLAG`](TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG).
    /// This method replaces all flags.
    #[must_use]
    pub(crate) const fn with_flags(mut self, flags: TacacsFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Adds [`TAC_PLUS_SINGLE_CONNECT_FLAG`](TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
    /// to the reply packet header flags.
    #[must_use]
    pub(crate) fn with_single_connect(mut self) -> Self {
        self.flags |= TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
        self
    }

    /// Delivers the reply after `delay` instead of immediately.
    #[must_use]
    pub(crate) const fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Obfuscates the reply packet before registering it.
    ///
    /// The mock transport replays raw bytes without deobfuscation. Thus, callers
    /// must obfuscate a reply before registration to simulate a TACACS+ server.
    #[must_use]
    pub(crate) const fn with_obfuscation_key(mut self, key: &'a [u8]) -> Self {
        self.obfuscation_key = Some(key);
        self
    }

    /// Builds the accounting reply packet and registers it on the coordinator.
    /// # Errors
    /// Returns an error if the reply packet cannot be constructed.
    pub(crate) async fn send(self) -> anyhow::Result<()> {
        let coordinator = self.coordinator;
        let delay = self.delay;
        let packet = self.build()?;

        if let Some(delay) = delay {
            coordinator.add_reply_with_delay(packet, delay).await
        } else {
            coordinator.add_reply(packet).await
        }
    }

    /// Builds the accounting reply packet without registering it.
    ///
    /// Use this when a test must register the packet with metadata that differs
    /// from its header. For example, this can test header-mismatch errors.
    /// # Errors
    /// Returns an error if the reply packet cannot be constructed.
    #[allow(clippy::cast_possible_truncation)] // body length bounded by u16 field sizes
    pub(crate) fn build(self) -> anyhow::Result<Packet> {
        let data = self.reply.to_bytes()?;
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

/// Builder for registering authorization reply packets on a [`MockTransportCoordinator`].
///
/// Create this builder through [`MockTransportCoordinator::authorization_reply`] or
/// [`MockTransportCoordinator::authorization_reply_for_id`]. Call [`send`](Self::send)
/// to finish construction and register the reply.
///
/// # Defaults
///
/// | Field | Default |
/// |-------|---------|
/// | `flags` | [`TAC_PLUS_UNENCRYPTED_FLAG`](TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG) |
/// | `delay` | `None` (immediate) |
/// | `obfuscation_key` | `None` (plaintext) |
pub(crate) struct MockAuthorizationReplyBuilder<'a> {
    coordinator: &'a MockTransportCoordinator,
    session_id: u32,
    seq_no: u8,
    reply: &'a AuthorizationReply,
    flags: TacacsFlags,
    delay: Option<Duration>,
    obfuscation_key: Option<&'a [u8]>,
}

impl<'a> MockAuthorizationReplyBuilder<'a> {
    /// Overrides the default flags on the reply packet header.
    ///
    /// The default is
    /// [`TAC_PLUS_UNENCRYPTED_FLAG`](TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG).
    /// This method replaces all flags.
    #[must_use]
    pub(crate) const fn with_flags(mut self, flags: TacacsFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Adds [`TAC_PLUS_SINGLE_CONNECT_FLAG`](TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
    /// to the reply packet header flags.
    #[must_use]
    pub(crate) fn with_single_connect(mut self) -> Self {
        self.flags |= TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
        self
    }

    /// Delivers the reply after `delay` instead of immediately.
    #[must_use]
    pub(crate) const fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Obfuscates the reply packet before registering it.
    ///
    /// The mock transport replays raw bytes without deobfuscation. Thus, callers
    /// must obfuscate a reply before registration to simulate a TACACS+ server.
    #[must_use]
    pub(crate) const fn with_obfuscation_key(mut self, key: &'a [u8]) -> Self {
        self.obfuscation_key = Some(key);
        self
    }

    /// Builds the authorization reply packet and registers it on the coordinator.
    /// # Errors
    /// Returns an error if the reply packet cannot be constructed.
    pub(crate) async fn send(self) -> anyhow::Result<()> {
        let coordinator = self.coordinator;
        let delay = self.delay;
        let packet = self.build()?;

        if let Some(delay) = delay {
            coordinator.add_reply_with_delay(packet, delay).await
        } else {
            coordinator.add_reply(packet).await
        }
    }

    /// Builds the authorization reply packet without registering it.
    ///
    /// Use this when a test must register the packet with metadata that differs
    /// from its header. For example, this can test header-mismatch errors.
    /// # Errors
    /// Returns an error if the reply packet cannot be constructed.
    #[allow(clippy::cast_possible_truncation)] // body length bounded by reply field sizes
    pub(crate) fn build(self) -> anyhow::Result<Packet> {
        let data = self.reply.to_bytes()?;
        let mut packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAuthorisation,
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
/// Get this handle through
/// [`MockTransport::coordinator()`](super::MockTransport::coordinator). An
/// `Arc<Mutex<..>>` shares `MockState` with the transport. Tests can keep this
/// handle after `MultiplexedConnection` consumes the transport.
///
/// # Concurrency
///
/// All methods acquire the shared async mutex. You can call them while the
/// connection runs, including during a conversation. Each method holds the
/// mutex only for a `HashMap` operation.
#[derive(Clone, Debug)]
pub(crate) struct MockTransportCoordinator {
    /// Shared state with the write processor task.
    pub(in crate::transport::mock) state: Arc<Mutex<MockState>>,
}

impl MockTransportCoordinator {
    /// Registers a reply packet. The write processor sends it when it
    /// receives a request with the same `session_id` and `seq_no - 1`.
    ///
    /// The session ID and sequence number are extracted from the packet header.
    /// # Errors
    /// Returns an error if the packet header cannot be read.
    pub(crate) async fn add_reply(&self, reply: Packet) -> anyhow::Result<()> {
        let session_id = reply.header().session_id;
        let seq_no = reply.header().seq_no;
        log::info!("Mock coordinator: registering reply for session {session_id}, seq_no {seq_no}");
        self.add_reply_bytes(session_id, seq_no, reply.to_bytes())
            .await
    }

    /// Registers raw serialized reply bytes for a session and sequence number.
    ///
    /// The other `add_reply*` methods use this method. Use it to control the byte
    /// representation, such as when a test requires a malformed packet.
    ///
    /// # Arguments
    ///
    /// * `session_id` — the TACACS+ session ID the reply belongs to.
    /// * `seq_no` — the sequence number of the reply (must be `request_seq + 1`).
    /// * `reply_bytes` — the complete serialized packet bytes.
    /// # Errors
    /// This method is infallible but returns `Result` for API consistency.
    pub(crate) async fn add_reply_bytes(
        &self,
        session_id: u32,
        seq_no: u8,
        reply_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        log::info!(
            "Mock coordinator: registering {} raw reply byte(s) for session {session_id}, seq_no {seq_no}",
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
        drop(state);
        Ok(())
    }

    /// Registers a reply packet with a specified delivery delay.
    ///
    /// Use this method to test timeout behavior. The write processor waits for
    /// `delay` before it sends the reply bytes.
    /// # Errors
    /// This method is infallible but returns `Result` for API consistency.
    pub(crate) async fn add_reply_with_delay(
        &self,
        reply: Packet,
        delay: Duration,
    ) -> anyhow::Result<()> {
        log::info!(
            "Mock coordinator: registering delayed reply ({delay:?}) for session {}, seq_no {}",
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
        drop(state);
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
    pub(crate) const fn accounting_reply<'a>(
        &'a self,
        session: &SharedSession,
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
    /// Use this instead of [`accounting_reply`](Self::accounting_reply) when no
    /// [`SharedSession`] is available. For example, dedicated-connection tests
    /// can use a predetermined session ID.
    #[must_use]
    pub(crate) const fn accounting_reply_for_id<'a>(
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

    /// Creates a [`MockAuthorizationReplyBuilder`] for registering an authorization
    /// reply associated with the given session.
    ///
    /// # Arguments
    ///
    /// * `session` - provides the session ID for the reply.
    /// * `reply_sequence_number` - the sequence number for the reply.
    /// * `reply` - the authorization reply body.
    pub(crate) const fn authorization_reply<'a>(
        &'a self,
        session: &SharedSession,
        reply_sequence_number: u8,
        reply: &'a AuthorizationReply,
    ) -> MockAuthorizationReplyBuilder<'a> {
        MockAuthorizationReplyBuilder {
            coordinator: self,
            session_id: session.session_id(),
            seq_no: reply_sequence_number,
            reply,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            delay: None,
            obfuscation_key: None,
        }
    }

    /// Creates a [`MockAuthorizationReplyBuilder`] for registering an authorization
    /// reply for a known `session_id`.
    ///
    /// Use this instead of [`authorization_reply`](Self::authorization_reply)
    /// when no [`SharedSession`] is available. For example,
    /// dedicated-connection tests can use a predetermined session ID.
    #[must_use]
    pub(crate) const fn authorization_reply_for_id<'a>(
        &'a self,
        session_id: u32,
        reply_sequence_number: u8,
        reply: &'a AuthorizationReply,
    ) -> MockAuthorizationReplyBuilder<'a> {
        MockAuthorizationReplyBuilder {
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
    /// The returned map is keyed by sequence number. It contains the packets
    /// that the connection wrote to the transport.
    ///
    /// The mock transport does not deobfuscate packets. It operates like a
    /// network capture. If the connection uses an obfuscation key, the returned
    /// packet bodies remain obfuscated. Call [`Packet::to_deobfuscated`] with the
    /// correct key before you inspect cleartext content.
    ///
    /// # Errors
    ///
    /// Returns an error if no requests have been recorded for `session_id`.
    pub(crate) async fn get_requests_for_session(
        &self,
        session_id: u32,
    ) -> anyhow::Result<HashMap<u8, Packet>> {
        let state = self.state.lock().await;
        let result = state.requests.get(&session_id).cloned();
        drop(state);

        let count = result.as_ref().map_or(0, std::collections::HashMap::len);
        log::debug!(
            "Mock coordinator: get_requests_for_session({session_id}) returned {count} request(s)"
        );
        result.ok_or_else(|| anyhow::anyhow!("No requests were recorded for session {session_id}"))
    }

    /// Returns unconsumed reply packets for the specified `session_id`.
    ///
    /// The write processor removes replies after it matches and sends them.
    /// Use this method to make sure that all expected replies were consumed.
    ///
    /// # Errors
    ///
    /// Returns an error if no replies are configured for `session_id`.
    pub(crate) async fn get_replies_for_session(
        &self,
        session_id: u32,
    ) -> anyhow::Result<HashMap<u8, Packet>> {
        let state = self.state.lock().await;
        let configured = state
            .replies
            .get(&session_id)
            .ok_or_else(|| anyhow::anyhow!("No replies are configured for session {session_id}"))?
            .clone();
        drop(state);

        log::debug!(
            "Mock coordinator: get_replies_for_session({session_id}) returned {} unconsumed reply(ies)",
            configured.len()
        );

        configured
            .iter()
            .map(|(seq, config)| Packet::from_bytes(&config.bytes).map(|p| (*seq, p)))
            .collect()
    }
}
