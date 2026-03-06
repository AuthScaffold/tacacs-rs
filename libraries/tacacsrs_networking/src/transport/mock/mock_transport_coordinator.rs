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
use crate::transport::mock::mock_transport::{MockState, ReplyConfig};

/// Control handle for configuring and inspecting a [`super::MockTransport`].
///
/// This handle can be held independently from the transport instance consumed by
/// `TacacsConnection::run()`, so tests do not need to clone the transport object.
#[derive(Clone, Debug)]
pub struct MockTransportCoordinator {
    pub(crate) state: Arc<Mutex<MockState>>,
}

impl MockTransportCoordinator {
    /// Add a reply packet.
    pub async fn add_reply(&self, reply: Packet) -> anyhow::Result<()> {
        self.add_reply_bytes(reply.header().session_id, reply.header().seq_no, reply.to_bytes())
            .await
    }

    /// Add raw binary reply bytes.
    pub async fn add_reply_bytes(
        &self,
        session_id: u32,
        seq_no: u8,
        reply_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
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

    /// Add a reply packet with delay.
    pub async fn add_reply_with_delay(&self, reply: Packet, delay: Duration) -> anyhow::Result<()> {
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

    /// Add an accounting reply.
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

    /// Add an accounting reply with delay.
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

    /// Add an accounting reply with explicit flags.
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

    /// Retrieve captured request packets for a session.
    pub async fn get_requests_for_session(
        &self,
        session_id: u32,
    ) -> anyhow::Result<HashMap<u8, Packet>> {
        let state = self.state.lock().await;
        state
            .requests
            .get(&session_id)
            .cloned()
            .ok_or_else(|| anyhow::Error::msg("No requests for session"))
    }

    /// Retrieve currently configured replies for a session.
    pub async fn get_replies_for_session(
        &self,
        session_id: u32,
    ) -> anyhow::Result<HashMap<u8, Packet>> {
        let state = self.state.lock().await;
        let configured = state
            .replies
            .get(&session_id)
            .ok_or_else(|| anyhow::Error::msg("No replies for session"))?;

        configured
            .iter()
            .map(|(seq, config)| Packet::from_bytes(&config.bytes).map(|p| (*seq, p)))
            .collect()
    }
}
