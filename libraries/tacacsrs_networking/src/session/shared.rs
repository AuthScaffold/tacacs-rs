use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::runtime::Handle;

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

    pub(crate) async fn complete(&self) {
        if !self.mark_complete() {
            return;
        }

        // Tell the session manager to remove this session from the registry.
        if let Some(mgr) = &self.manager {
            mgr.remove_session(self.id).await;
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

        let Some(manager) = self.manager.clone() else {
            return;
        };

        let session_id = self.id;

        match Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    manager.remove_session(session_id).await;
                });
            }
            Err(_) => {
                log::warn!(
                    target: "tacacsrs_networking::session::shared::drop",
                    "Cannot schedule registry cleanup for dropped session {session_id}: no Tokio runtime is available"
                );
            }
        }
    }
}
