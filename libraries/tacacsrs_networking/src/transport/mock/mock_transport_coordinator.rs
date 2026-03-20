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
/// The mutex is held only for the duration of the HashMap insert/lookup.
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

    /// Convenience method: builds and registers an accounting reply packet with
    /// the default unencrypted flag.
    ///
    /// # Arguments
    ///
    /// * `session` — the session to associate the reply with (provides the session ID).
    /// * `reply_sequence_number` — the sequence number for the reply.
    /// * `reply` — the accounting reply body.
    pub async fn add_accounting_reply(
        &self,
        session: &Session,
        reply_sequence_number: u8,
        reply: &AccountingReply,
    ) -> anyhow::Result<()> {
        self.add_accounting_reply_with_flags(
            session,
            reply_sequence_number,
            reply,
            TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
        )
        .await
    }

    /// Same as [`add_accounting_reply`](Self::add_accounting_reply), but delivered
    /// after a specified delay (see [`add_reply_with_delay`](Self::add_reply_with_delay)).
    pub async fn add_accounting_reply_with_delay(
        &self,
        session: &Session,
        reply_sequence_number: u8,
        reply: &AccountingReply,
        delay: Duration,
    ) -> anyhow::Result<()> {
        let data = reply.to_bytes();
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: reply_sequence_number,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: session.session_id(),
                length: data.len() as u32,
            },
            data,
        )?;
        self.add_reply_with_delay(packet, delay).await
    }

    /// Builds and registers an accounting reply packet with caller-specified
    /// TACACS+ flags (e.g. encrypted vs unencrypted).
    pub async fn add_accounting_reply_with_flags(
        &self,
        session: &Session,
        reply_sequence_number: u8,
        reply: &AccountingReply,
        flags: TacacsFlags,
    ) -> anyhow::Result<()> {
        let data = reply.to_bytes();
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: reply_sequence_number,
                flags,
                session_id: session.session_id(),
                length: data.len() as u32,
            },
            data,
        )?;
        self.add_reply(packet).await
    }

    /// Builds and registers an accounting reply for a known `session_id`.
    ///
    /// This is the counterpart of [`add_accounting_reply_with_flags`](Self::add_accounting_reply_with_flags)
    /// for callers that do not have a [`Session`] reference — e.g. when
    /// testing [`DedicatedConnection`](crate::DedicatedConnection) with a
    /// predetermined session ID.
    pub async fn add_accounting_reply_for_session_id(
        &self,
        session_id: u32,
        reply_sequence_number: u8,
        reply: &AccountingReply,
        flags: TacacsFlags,
    ) -> anyhow::Result<()> {
        let data = reply.to_bytes();
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: reply_sequence_number,
                flags,
                session_id,
                length: data.len() as u32,
            },
            data,
        )?;
        self.add_reply(packet).await
    }

    /// Builds, obfuscates, and registers an accounting reply for a known
    /// `session_id`.
    ///
    /// The packet is constructed with the given `flags` (which should
    /// include [`TAC_PLUS_UNENCRYPTED_FLAG`](TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG))
    /// and then obfuscated with `obfuscation_key` via
    /// [`Packet::to_obfuscated`]. The mock transport replays raw bytes, so
    /// the reply must be pre-obfuscated to match what a real server would
    /// send.
    pub async fn add_obfuscated_accounting_reply_for_session_id(
        &self,
        session_id: u32,
        reply_sequence_number: u8,
        reply: &AccountingReply,
        flags: TacacsFlags,
        obfuscation_key: &[u8],
    ) -> anyhow::Result<()> {
        let data = reply.to_bytes();
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: reply_sequence_number,
                flags,
                session_id,
                length: data.len() as u32,
            },
            data,
        )?
        .to_obfuscated(obfuscation_key);
        self.add_reply(packet).await
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
        let count = result.as_ref().map_or(0, |m| m.len());
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
