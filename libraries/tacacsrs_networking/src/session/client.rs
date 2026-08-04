//! Public client session facade.

use async_trait::async_trait;

use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::packet::Packet;

use super::{DedicatedSession, SharedSession};

/// A client session returned by [`TacacsClient`](crate::TacacsClient).
///
/// This type implements [`ClientSessionFlowIoTrait`] and hides whether the
/// current operation is running over a dedicated stream or a shared multiplexed
/// connection.
pub struct ClientSession {
    inner: ClientSessionInner,
}

enum ClientSessionInner {
    Shared(SharedSession),
    Dedicated(DedicatedSession),
}

impl ClientSession {
    pub(crate) fn shared(session: SharedSession) -> Self {
        Self {
            inner: ClientSessionInner::Shared(session),
        }
    }

    pub(crate) fn dedicated(session: DedicatedSession) -> Self {
        Self {
            inner: ClientSessionInner::Dedicated(session),
        }
    }

    pub(crate) fn session_id(&self) -> u32 {
        match &self.inner {
            ClientSessionInner::Shared(session) => session.session_id(),
            ClientSessionInner::Dedicated(session) => session.session_id(),
        }
    }

    pub(crate) async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
        match &self.inner {
            ClientSessionInner::Shared(session) => session.send_packet(packet).await,
            ClientSessionInner::Dedicated(session) => session.send_packet(packet).await,
        }
    }

    pub(crate) async fn receive_packet(&self) -> anyhow::Result<Packet> {
        match &self.inner {
            ClientSessionInner::Shared(session) => session.receive_packet().await,
            ClientSessionInner::Dedicated(session) => session.receive_packet().await,
        }
    }

    pub(crate) async fn complete(&self) {
        match &self.inner {
            ClientSessionInner::Shared(session) => session.complete().await,
            ClientSessionInner::Dedicated(session) => session.complete().await,
        }
    }
}

#[async_trait]
impl ClientSessionFlowIoTrait for ClientSession {
    async fn is_complete(&self) -> bool {
        match &self.inner {
            ClientSessionInner::Shared(session) => session.is_complete().await,
            ClientSessionInner::Dedicated(session) => session.is_complete(),
        }
    }

    async fn next_sequence_number(&self) -> u8 {
        match &self.inner {
            ClientSessionInner::Shared(session) => session.next_sequence_number().await,
            ClientSessionInner::Dedicated(session) => session.next_sequence_number().await,
        }
    }

    fn session_id(&self) -> u32 {
        Self::session_id(self)
    }

    async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
        Self::send_packet(self, packet).await
    }

    async fn receive_packet(&self) -> anyhow::Result<Packet> {
        Self::receive_packet(self).await
    }

    async fn complete(&self) {
        Self::complete(self).await;
    }
}
