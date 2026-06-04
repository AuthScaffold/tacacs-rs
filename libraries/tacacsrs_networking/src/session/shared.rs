use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::runtime::Handle;
use tokio::sync::RwLock;

use tacacsrs_messages::packet::Packet;

use super::{DuplexChannel, SessionManager};

pub(crate) struct SharedSession {
    id: u32,
    duplex_channel: DuplexChannel,

    current_sequence_number: RwLock<u8>,
    complete: AtomicBool,
    manager: Option<Arc<SessionManager>>,
}

impl SharedSession {
    #[cfg(test)]
    pub(crate) fn new(session_id: u32, duplex_channel: DuplexChannel) -> Self {
        Self {
            id: session_id,
            duplex_channel,
            current_sequence_number: 1_u8.into(),
            complete: AtomicBool::new(false),
            manager: None,
        }
    }

    pub(crate) fn new_with_manager(
        session_id: u32,
        duplex_channel: DuplexChannel,
        manager: Option<Arc<SessionManager>>,
    ) -> Self {
        Self {
            id: session_id,
            duplex_channel,
            current_sequence_number: 1_u8.into(),
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

    pub(crate) async fn next_sequence_number(&self) -> u8 {
        let mut sequence_number_lock = self.current_sequence_number.write().await;
        let sequence_number = *sequence_number_lock;
        *sequence_number_lock = sequence_number.wrapping_add(2);

        sequence_number
    }

    pub(crate) async fn complete(&self) {
        if !self.mark_complete() {
            return;
        }

        // Notify the session manager to remove this session from the registry
        if let Some(mgr) = &self.manager {
            mgr.remove_session(self.id).await;
        }
    }

    pub(crate) async fn is_complete(&self) -> bool {
        if self.duplex_channel.sender_closed() {
            return true;
        }

        if self.duplex_channel.receiver_closed().await {
            return true;
        }

        self.complete.load(Ordering::Acquire)
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
                    "Dropping session {session_id} without a Tokio runtime; session registry cleanup could not be scheduled"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacacsrs_messages::packet::Packet;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_session() {
        let (network_sender, _network_receiver) = mpsc::channel::<Packet>(32);
        let (_client_sender, client_receiver) = mpsc::channel::<Packet>(32);
        let duplex_channel = DuplexChannel::new(client_receiver, network_sender);

        let session = SharedSession::new(1, duplex_channel);

        assert_eq!(session.session_id(), 1);
        assert!(!(session.is_complete().await));

        session.complete().await;

        assert!(session.is_complete().await);
    }

    #[tokio::test]
    async fn test_sequence_number() {
        let (network_sender, _network_receiver) = mpsc::channel::<Packet>(32);
        let (_client_sender, client_receiver) = mpsc::channel::<Packet>(32);
        let duplex_channel = DuplexChannel::new(client_receiver, network_sender);

        let session = SharedSession::new(1, duplex_channel);

        assert_eq!(session.next_sequence_number().await, 1);
        assert_eq!(session.next_sequence_number().await, 3);
        assert_eq!(session.next_sequence_number().await, 5);

        assert!(!(session.is_complete().await));
    }

    #[tokio::test]
    async fn test_is_complete_network_closed() {
        let (network_sender, network_receiver) = mpsc::channel::<Packet>(32);
        let (client_sender, client_receiver) = mpsc::channel::<Packet>(32);
        let duplex_channel = DuplexChannel::new(client_receiver, network_sender);

        let session = SharedSession::new(1, duplex_channel);
        assert!(!(session.is_complete().await));

        // Close the client sender, this should propagate to the session
        drop(client_sender);

        // session is complete because the client sender is closed
        assert!(session.is_complete().await);

        // the client sender is still open because it'll be used by many sessions
        assert!(!network_receiver.is_closed());
        assert!(!(session.duplex_channel.sender_closed()));

        // the client receiver is closed
        assert!(session.duplex_channel.receiver_closed().await);
    }
}
