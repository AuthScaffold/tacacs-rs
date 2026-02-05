use std::sync::Arc;
use tokio::sync::RwLock;

use crate::duplex_channel::DuplexChannel;
use crate::session_manager::SessionManager;


pub struct Session
{
    pub session_id: u32,
    pub duplex_channel: DuplexChannel,

    pub current_sequence_number: RwLock<u8>,
    pub session_complete: RwLock<bool>,
    session_manager: Option<Arc<SessionManager>>
}


impl Session
{
    pub fn new(session_id: u32, duplex_channel: DuplexChannel) -> Self
    {
        Self::new_with_manager(session_id, duplex_channel, None)
    }

    pub fn new_with_manager(session_id: u32, duplex_channel: DuplexChannel, session_manager: Option<Arc<SessionManager>>) -> Self
    {
        Self
        {
            session_id,
            duplex_channel,
            current_sequence_number: 1_u8.into(),
            session_complete: false.into(),
            session_manager
        }
    }

    pub fn session_id(&self) -> u32
    {
        self.session_id
    }

    pub async fn next_sequence_number(&self) -> u8
    {
        let mut sequence_number_lock = self.current_sequence_number.write().await;
        let sequence_number = *sequence_number_lock;
        *sequence_number_lock = sequence_number.wrapping_add(2);

        sequence_number
    }

    pub async fn complete(&self)
    {
        let mut session_complete_lock = self.session_complete.write().await;
        *session_complete_lock = true;
        drop(session_complete_lock);

        // Notify the session manager to remove this session from the registry
        if let Some(manager) = &self.session_manager {
            manager.remove_session(self.session_id).await;
        }
    }

    pub async fn is_complete(&self) -> bool
    {
        if self.duplex_channel.sender_closed().await
        {
            return true;
        }

        if self.duplex_channel.receiver_closed().await
        {
            return true;
        }

        let session_complete_lock = self.session_complete.read().await;
        *session_complete_lock
    }
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::duplex_channel::DuplexChannel;
    use tacacsrs_messages::packet::Packet;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_session()
    {
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
    async fn test_sequence_number()
    {
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
    async fn test_is_complete_network_closed()
    {
        let (network_sender, _network_receiver) = mpsc::channel::<Packet>(32);
        let (_client_sender, client_receiver) = mpsc::channel::<Packet>(32);
        let duplex_channel = DuplexChannel::new(client_receiver, network_sender);

        let session = Session::new(1, duplex_channel);
        assert!(!(session.is_complete().await));

        // Close the client sender, this should propagate to the session
        drop(_client_sender);

        // session is complete because the client sender is closed
        assert!(session.is_complete().await);

        // the client sender is still open because it'll be used by many sessions
        assert!(!_network_receiver.is_closed());
        assert!(!(session.duplex_channel.sender_closed().await));

        // the client receiver is closed
        assert!(session.duplex_channel.receiver_closed().await);
    }
}