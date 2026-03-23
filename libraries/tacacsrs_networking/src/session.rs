use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::sync::RwLock;

use crate::duplex_channel::DuplexChannel;
use crate::session_manager::SessionManager;


pub struct Session {
    pub session_id: u32,
    pub duplex_channel: DuplexChannel,

    pub current_sequence_number: RwLock<u8>,
    pub session_complete: AtomicBool,
    manager: Option<Arc<SessionManager>>,
}


impl Session {
    pub fn new(session_id: u32, duplex_channel: DuplexChannel) -> Self {
        Self {
            session_id,
            duplex_channel,
            current_sequence_number: 1_u8.into(),
            session_complete: AtomicBool::new(false),
            manager: None,
        }
    }

    pub fn new_with_manager(
        session_id: u32,
        duplex_channel: DuplexChannel,
        manager: Option<Arc<SessionManager>>,
    ) -> Self {
        Self {
            session_id,
            duplex_channel,
            current_sequence_number: 1_u8.into(),
            session_complete: AtomicBool::new(false),
            manager,
        }
    }

    fn mark_complete(&self) -> bool {
        !self.session_complete.swap(true, Ordering::AcqRel)
    }

    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    pub async fn next_sequence_number(&self) -> u8 {
        let mut sequence_number_lock = self.current_sequence_number.write().await;
        let sequence_number = *sequence_number_lock;
        *sequence_number_lock = sequence_number.wrapping_add(2);

        sequence_number
    }

    pub async fn complete(&self) {
        if !self.mark_complete() {
            return;
        }

        // Notify the session manager to remove this session from the registry
        if let Some(mgr) = &self.manager {
            mgr.remove_session(self.session_id).await;
        }
    }

    pub async fn is_complete(&self) -> bool {
        if self.duplex_channel.sender_closed() {
            return true;
        }

        if self.duplex_channel.receiver_closed().await {
            return true;
        }

        self.session_complete.load(Ordering::Acquire)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.mark_complete() {
            return;
        }

        let Some(manager) = self.manager.clone() else {
            return;
        };

        let session_id = self.session_id;

        match Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    manager.remove_session(session_id).await;
                });
            }
            Err(_) => {
                log::warn!(
                    target: "tacacsrs_networking::session::drop",
                    "Dropping session {session_id} without a Tokio runtime; session registry cleanup could not be scheduled"
                );
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::duplex_channel::DuplexChannel;
    use tacacsrs_messages::packet::Packet;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_session() {
        let (network_sender, _network_receiver) = mpsc::channel::<Packet>(32);
        let (_client_sender, client_receiver) = mpsc::channel::<Packet>(32);
        let duplex_channel = DuplexChannel::new(client_receiver, network_sender);

        let session = Session::new(1, duplex_channel);

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

        let session = Session::new(1, duplex_channel);

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

        let session = Session::new(1, duplex_channel);
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
