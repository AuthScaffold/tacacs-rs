//! Mutable TACACS+ client conversations.

use anyhow::Context;
use tacacsrs_protocol::conversation::ConversationState;
use tacacsrs_protocol::packet::{Packet, PacketTrait};

use super::ClientSession;

/// A sequential TACACS+ conversation over a dedicated or shared connection.
///
/// Each call to [`round_trip`](Self::round_trip) sends one odd-sequence client
/// packet and waits for the corresponding even-sequence server reply. The
/// conversation enforces one session identifier, packet type, protocol
/// version, and monotonically increasing sequence numbers.
///
/// Keep the originating [`crate::TacacsClient`] alive while using a conversation.
/// Dropping that client closes its transports. Terminal client shutdown can also
/// force a retained conversation closed when its drain deadline expires.
pub struct ClientConversation {
    session: Option<ClientSession>,
    state: ConversationState,
}

impl ClientConversation {
    pub(crate) fn new(session: ClientSession) -> Self {
        Self {
            state: ConversationState::new(session.session_id()),
            session: Some(session),
        }
    }

    /// Returns the active session identifier, or `None` after completion.
    #[must_use]
    pub fn session_id(&self) -> Option<u32> {
        self.session.as_ref().map(ClientSession::session_id)
    }

    /// Sends one request and receives its matching reply.
    ///
    /// The client automatically completes the conversation when packet I/O or
    /// response validation fails. A caller can explicitly complete a successful
    /// conversation after receiving a terminal protocol reply.
    ///
    /// # Errors
    ///
    /// Returns an error for an inactive conversation, invalid request metadata,
    /// packet I/O failure, or a response that does not match the request.
    pub async fn round_trip(&mut self, request: Packet) -> anyhow::Result<Packet> {
        self.state.validate_request(request.header())?;
        let result = self.round_trip_inner(request).await;
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
        self.state.complete();
    }

    async fn round_trip_inner(&mut self, request: Packet) -> anyhow::Result<Packet> {
        let session = self
            .session
            .as_ref()
            .context("TACACS+ conversation is complete")?;
        let _reply_wait = session.awaiting_reply(&request);
        session.send_packet(request).await?;
        let response = session.receive_packet().await?;
        self.state.validate_response(response.header())?;
        session.record_terminal_reply(&response);
        Ok(response)
    }
}
