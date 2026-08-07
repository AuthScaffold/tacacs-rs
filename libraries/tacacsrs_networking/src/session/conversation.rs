//! Mutable TACACS+ client conversations.

use anyhow::Context;
use tacacsrs_messages::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::packet::{Packet, PacketTrait};

use super::ClientSession;

/// A sequential TACACS+ conversation over a dedicated or shared connection.
///
/// Each call to [`round_trip`](Self::round_trip) sends one odd-sequence client
/// packet and waits for the corresponding even-sequence server reply. The
/// conversation enforces one session identifier, packet type, protocol
/// version, and monotonically increasing sequence numbers.
pub struct ClientConversation {
    session: Option<ClientSession>,
    packet_type: Option<TacacsType>,
    minor_version: Option<TacacsMinorVersion>,
    next_request_sequence: Option<u8>,
}

impl ClientConversation {
    pub(crate) fn new(session: ClientSession) -> Self {
        Self {
            session: Some(session),
            packet_type: None,
            minor_version: None,
            next_request_sequence: Some(1),
        }
    }

    /// Returns the active session identifier, or `None` after completion.
    #[must_use]
    pub fn session_id(&self) -> Option<u32> {
        self.session.as_ref().map(ClientSession::session_id)
    }

    /// Sends one request and receives its matching reply.
    ///
    /// The conversation is completed automatically when packet I/O or response
    /// validation fails. A caller may explicitly complete a successful
    /// conversation after receiving a terminal protocol reply.
    ///
    /// # Errors
    ///
    /// Returns an error for an inactive conversation, invalid request metadata,
    /// packet I/O failure, or a response that does not match the request.
    pub async fn round_trip(&mut self, request: Packet) -> anyhow::Result<Packet> {
        let request_sequence = self.validate_request(&request)?;
        let result = self.round_trip_inner(request, request_sequence).await;
        if result.is_err() {
            self.complete().await;
        }
        result
    }

    /// Completes the conversation and releases its session route.
    pub async fn complete(&mut self) {
        if let Some(session) = self.session.take() {
            session.complete().await;
        }
        self.next_request_sequence = None;
    }

    fn validate_request(&mut self, request: &Packet) -> anyhow::Result<u8> {
        let session = self
            .session
            .as_ref()
            .context("TACACS+ conversation is complete")?;
        let header = request.header();
        let expected_sequence = self
            .next_request_sequence
            .context("TACACS+ conversation exhausted its sequence numbers")?;

        if header.session_id != session.session_id() {
            anyhow::bail!(
                "TACACS+ conversation session mismatch: request={:#x}, expected={:#x}",
                header.session_id,
                session.session_id(),
            );
        }
        if header.major_version != TacacsMajorVersion::TacacsPlusMajor1 {
            anyhow::bail!("TACACS+ conversation requires protocol major version 1");
        }
        if header.seq_no != expected_sequence {
            anyhow::bail!(
                "unexpected TACACS+ conversation request sequence {}; expected {}",
                header.seq_no,
                expected_sequence,
            );
        }
        match self.packet_type {
            Some(packet_type) if packet_type != header.tacacs_type => {
                anyhow::bail!("TACACS+ conversation packet type changed")
            }
            Some(_) => {}
            None => self.packet_type = Some(header.tacacs_type),
        }
        match self.minor_version {
            Some(minor_version) if minor_version != header.minor_version => {
                anyhow::bail!("TACACS+ conversation minor version changed")
            }
            Some(_) => {}
            None => self.minor_version = Some(header.minor_version),
        }

        Ok(expected_sequence)
    }

    async fn round_trip_inner(
        &mut self,
        request: Packet,
        request_sequence: u8,
    ) -> anyhow::Result<Packet> {
        let session = self
            .session
            .as_ref()
            .context("TACACS+ conversation is complete")?;
        let packet_type = self
            .packet_type
            .context("conversation packet type was not recorded")?;
        let minor_version = self
            .minor_version
            .context("conversation minor version was not recorded")?;
        let expected_response_sequence = request_sequence
            .checked_add(1)
            .context("TACACS+ conversation response sequence would wrap")?;

        session.send_packet(request).await?;
        let response = session.receive_packet().await?;
        let header = response.header();
        if header.session_id != session.session_id()
            || header.major_version != TacacsMajorVersion::TacacsPlusMajor1
            || header.minor_version != minor_version
            || header.tacacs_type != packet_type
            || header.seq_no != expected_response_sequence
        {
            anyhow::bail!(
                "unexpected TACACS+ conversation response header for session {:#x}: seq_no={}, type={}, version={:?}.{:?}",
                header.session_id,
                header.seq_no,
                header.tacacs_type,
                header.major_version,
                header.minor_version,
            );
        }

        self.next_request_sequence = request_sequence.checked_add(2);
        Ok(response)
    }
}
