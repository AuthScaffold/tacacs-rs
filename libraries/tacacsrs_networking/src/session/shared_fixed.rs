//! One-shot sessions over a multiplexed TACACS+ connection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use tacacsrs_messages::packet::Packet;
use tokio::runtime::Handle;
use tokio::sync::{Mutex, mpsc, oneshot};

use super::SessionManager;

pub(crate) struct SharedFixedSession {
    id: u32,
    outbound: mpsc::Sender<Packet>,
    response: Mutex<Option<oneshot::Receiver<anyhow::Result<Packet>>>>,
    complete: AtomicBool,
    manager: Arc<SessionManager>,
}

impl SharedFixedSession {
    pub(crate) fn new(
        id: u32,
        outbound: mpsc::Sender<Packet>,
        response: oneshot::Receiver<anyhow::Result<Packet>>,
        manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            id,
            outbound,
            response: Mutex::new(Some(response)),
            complete: AtomicBool::new(false),
            manager,
        }
    }

    pub(crate) const fn session_id(&self) -> u32 {
        self.id
    }

    pub(crate) async fn round_trip(&self, packet: Packet) -> anyhow::Result<Packet> {
        let receiver = self
            .response
            .lock()
            .await
            .take()
            .context("fixed TACACS+ response was already awaited")?;
        self.outbound
            .send(packet)
            .await
            .context("multiplexed TACACS+ writer is closed")?;
        receiver
            .await
            .context("multiplexed TACACS+ connection closed before the fixed response arrived")?
    }

    fn mark_complete(&self) -> bool {
        !self.complete.swap(true, Ordering::AcqRel)
    }

    pub(crate) async fn complete(&self) {
        if self.mark_complete() {
            self.manager.remove_session(self.id).await;
        }
    }
}

impl Drop for SharedFixedSession {
    fn drop(&mut self) {
        if !self.mark_complete() {
            return;
        }
        let manager = Arc::clone(&self.manager);
        let session_id = self.id;
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                manager.remove_session(session_id).await;
            });
        } else {
            log::warn!(
                "Cannot schedule registry cleanup for dropped fixed TACACS+ session {session_id:#x}: no Tokio runtime is available"
            );
        }
    }
}
