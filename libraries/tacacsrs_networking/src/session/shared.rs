use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tacacsrs_messages::packet::Packet;

use super::{DuplexChannel, SessionManager};

pub(crate) struct SharedSession {
    id: u32,
    duplex_channel: DuplexChannel,

    complete: AtomicBool,
    manager: Option<Arc<SessionManager>>,
}

impl SharedSession {
    pub(crate) fn new_with_manager(
        session_id: u32,
        duplex_channel: DuplexChannel,
        manager: Option<Arc<SessionManager>>,
    ) -> Self {
        Self {
            id: session_id,
            duplex_channel,
            complete: AtomicBool::new(false),
            manager,
        }
    }

    fn mark_complete(&self) -> bool {
        !self.complete.swap(true, Ordering::AcqRel)
    }

    pub(crate) const fn session_id(&self) -> u32 {
        self.id
    }

    pub(crate) fn complete(&self) {
        if !self.mark_complete() {
            return;
        }

        // Tell the session manager to remove this session from the registry.
        if let Some(mgr) = &self.manager {
            mgr.remove_session(self.id);
        }
    }

    pub(crate) async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
        self.duplex_channel.send_packet(packet).await
    }

    pub(crate) async fn receive_packet(&self) -> anyhow::Result<Packet> {
        self.duplex_channel.receive_packet().await
    }

    #[cfg(test)]
    pub(crate) async fn close_receiver(&self) {
        self.duplex_channel.close_receiver().await;
    }
}

impl Drop for SharedSession {
    fn drop(&mut self) {
        if !self.mark_complete() {
            return;
        }

        if let Some(manager) = &self.manager {
            manager.remove_session(self.id);
        }
    }
}
