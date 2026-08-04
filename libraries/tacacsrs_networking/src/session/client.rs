//! Internal client session transport facade.

use tacacsrs_messages::packet::Packet;

use super::{DedicatedSession, SharedSession};

/// Hides whether an operation uses a dedicated or shared transport.
pub(crate) struct ClientSession {
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

    pub(crate) async fn fixed_round_trip(&self, packet: Packet) -> anyhow::Result<Packet> {
        match &self.inner {
            ClientSessionInner::Shared(session) => session.fixed_round_trip(packet).await,
            ClientSessionInner::Dedicated(session) => {
                session.send_packet(packet).await?;
                session.receive_packet().await
            }
        }
    }

    pub(crate) async fn complete(&self) {
        match &self.inner {
            ClientSessionInner::Shared(session) => session.complete().await,
            ClientSessionInner::Dedicated(session) => session.complete().await,
        }
    }
}
