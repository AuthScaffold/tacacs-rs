use std::collections::HashMap;
use std::sync::Arc;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use tokio::sync::{mpsc, Mutex, RwLock};

use crate::duplex_channel::DuplexChannel;
use crate::session::Session;

#[derive(Debug)]
pub struct SessionManager {
    pub(crate) duplex_channels: RwLock<HashMap<u32, mpsc::Sender<Packet>>>,
    pub(crate) sender: tokio::sync::mpsc::Sender<Packet>,
    pub(crate) receiver: Mutex<Option<tokio::sync::mpsc::Receiver<Packet>>>,
    
    can_accept_new_sessions: RwLock<bool>
}

impl SessionManager
{
    pub(crate) fn new() -> Self
    {
        let (sender, receiver) = mpsc::channel::<Packet>(32);

        Self
        {
            duplex_channels: HashMap::new().into(),
            sender,
            receiver: Some(receiver).into(),
            can_accept_new_sessions: true.into()
        }
    }

    pub(crate) async fn disable_new_sessions(&self)
    {
        let mut can_accept_lock = self.can_accept_new_sessions.write().await;
        *can_accept_lock = false;
    }

    pub(crate) async fn create_channel(&self) -> anyhow::Result<(DuplexChannel, u32)>
    {
        self.create_channel_with_optional_id(None).await
    }

    pub(crate) async fn create_channel_with_id(&self, session_id: u32) -> anyhow::Result<(DuplexChannel, u32)>
    {
        self.create_channel_with_optional_id(Some(session_id)).await
    }

    async fn create_channel_with_optional_id(&self, custom_session_id: Option<u32>) -> anyhow::Result<(DuplexChannel, u32)>
    {
        // First, determine the session ID and validate it before creating any channels
        let session_id = {
            let duplex_channels = self.duplex_channels.read().await;

            match custom_session_id {
                Some(id) => {
                    // If a custom session ID is provided, check if it already exists and is still active
                    if let Some(existing_sender) = duplex_channels.get(&id) {
                        if !existing_sender.is_closed() {
                            return Err(anyhow::Error::msg(format!(
                                "Session ID {} is already in use",
                                id
                            )));
                        }
                        // Existing session is complete (channel closed), allow reuse
                        log::debug!(
                            target: "tacacsrs_networking::session_manager::create_channel",
                            "Reusing completed session ID {}",
                            id
                        );
                    }
                    id
                }
                None => {
                    // Generate new session id, regenerate if it already exists
                    let mut id = rand::random::<u32>();
                    while duplex_channels.contains_key(&id) {
                        id = rand::random::<u32>();
                    }
                    id
                }
            }
        };

        // Now create the channels after validation
        let (session_sender, session_receiver) = mpsc::channel::<Packet>(32);
        let duplex_channel = DuplexChannel::new(session_receiver, self.sender.clone());

        // Insert the new session
        {
            let mut duplex_channels = self.duplex_channels.write().await;
            duplex_channels.insert(session_id, session_sender);
        }

        Ok((duplex_channel, session_id))
    }


    pub async fn can_create_sessions(&self) -> bool
    {
        let can_accept_lock = self.can_accept_new_sessions.read().await;
        *can_accept_lock
    }

    pub async fn create_session(self: &Arc<Self>) -> anyhow::Result<Session>
    {
        self.create_session_with_optional_id(None).await
    }

    pub async fn create_session_with_id(self: &Arc<Self>, session_id: u32) -> anyhow::Result<Session>
    {
        self.create_session_with_optional_id(Some(session_id)).await
    }

    async fn create_session_with_optional_id(self: &Arc<Self>, custom_session_id: Option<u32>) -> anyhow::Result<Session>
    {
        if !self.can_create_sessions().await
        {
            return Err(anyhow::Error::msg("Connection is not accepting new sessions"));
        }

        let (duplex_channel, session_id) = match custom_session_id {
            Some(id) => self.create_channel_with_id(id).await?,
            None => self.create_channel().await?,
        };

        log::info!(
            target: "tacacsrs_networking::connection::create_session",
            "Created session with id: {}{}",
            session_id,
            if custom_session_id.is_some() { " (custom)" } else { "" }
        );

        Ok(Session::new_with_manager(session_id, duplex_channel, Some(Arc::clone(self))))
    }

    pub async fn remove_session(&self, session_id: u32)
    {
        let mut duplex_channels = self.duplex_channels.write().await;
        if duplex_channels.remove(&session_id).is_some() {
            log::info!(
                target: "tacacsrs_networking::session_manager::remove_session",
                "Removed session {} from duplex_channels registry",
                session_id
            );
        }
    }

    /// Closes all sessions by clearing the duplex_channels registry.
    /// This will cause any sessions waiting on channel receivers to receive None,
    /// allowing them to terminate gracefully.
    pub async fn close_all_sessions(&self)
    {
        let mut duplex_channels = self.duplex_channels.write().await;
        let session_count = duplex_channels.len();
        duplex_channels.clear();
        
        log::info!(
            target: "tacacsrs_networking::session_manager::close_all_sessions",
            "Closed all {} sessions from duplex_channels registry",
            session_count
        );
    }

    pub async fn send_message_to_session(&self, packet: Packet) -> anyhow::Result<()>
    {
        // Get a read lock on the duplex_channels dictionary and 
        // find the appropriate channel to forward the packet to.
        let duplex_channels = self.duplex_channels.read().await;
        let session_id = packet.header().session_id;

        match duplex_channels.get(&session_id) {
            Some(channel) => {
                log::info!(
                    target: "tacacsrs_networking::session_manager::send_message_to_session",
                    "Found client channel for session id {}, forwarding packet",
                    session_id
                );

                match channel.send(packet).await
                {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        log::warn!(
                            target: "tacacsrs_networking::session_manager::send_message_to_session",
                            "Failed to send packet to client channel for session id: {} due to error: {}",
                            session_id, e.to_string()
                        );

                        Err(anyhow::Error::msg("Failed to send packet to client channel"))
                    }
                }
            },
            
            None => {
                Err(anyhow::Error::msg("No client channel found for session id"))
            }
        }
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[tokio::test]
    async fn test_create_channel()
    {
        let session_manager = SessionManager::new();

        let (_, session_id) = session_manager.create_channel().await.unwrap();

        assert_ne!(session_id, 0);
    }

    #[tokio::test]
    async fn test_create_channel_with_existing_session_id()
    {
        let session_manager = SessionManager::new();

        let (_, session_id) = session_manager.create_channel().await.unwrap();
        let (_, session_id2) = session_manager.create_channel().await.unwrap();

        assert_ne!(session_id, session_id2);
    }

    #[tokio::test]
    async fn test_create_session()
    {
        let session_manager = Arc::new(SessionManager::new());

        let session = session_manager.create_session().await.unwrap();

        assert_ne!(session.session_id(), 0);
    }


    #[tokio::test]
    async fn test_create_session_when_connection_is_not_accepting_new_sessions()
    {
        let session_manager = Arc::new(SessionManager::new());

        session_manager.disable_new_sessions().await;

        let result = session_manager.create_session().await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_session_when_connection_is_not_accepting_new_sessions_and_has_existing_sessions()
    {
        let session_manager = Arc::new(SessionManager::new());

        // creating a session when connection is ok should succeed
        _ = session_manager.create_session().await.unwrap();

        session_manager.disable_new_sessions().await;

        // creating a session when connection is not accepting new sessions should fail
        let result = session_manager.create_session().await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_session_with_custom_id()
    {
        let session_manager = Arc::new(SessionManager::new());

        let custom_id = 12345678_u32;
        let session = session_manager.create_session_with_id(custom_id).await.unwrap();

        assert_eq!(session.session_id(), custom_id);
    }

    #[tokio::test]
    async fn test_create_session_with_duplicate_custom_id_fails()
    {
        let session_manager = Arc::new(SessionManager::new());

        let custom_id = 12345678_u32;
        
        // First session with custom ID should succeed
        let _session1 = session_manager.create_session_with_id(custom_id).await.unwrap();

        // Second session with same custom ID should fail
        let result = session_manager.create_session_with_id(custom_id).await;
        
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(err_msg.contains("already in use"), "Expected 'already in use' error, got: {}", err_msg);
    }

    #[tokio::test]
    async fn test_create_channel_with_custom_id()
    {
        let session_manager = SessionManager::new();

        let custom_id = 87654321_u32;
        let (_, session_id) = session_manager.create_channel_with_id(custom_id).await.unwrap();

        assert_eq!(session_id, custom_id);
    }

    #[tokio::test]
    async fn test_create_session_with_same_id_after_completion()
    {
        let session_manager = Arc::new(SessionManager::new());

        let custom_id = 99999999_u32;
        
        // Create first session with custom ID
        let session1 = session_manager.create_session_with_id(custom_id).await.unwrap();
        assert_eq!(session1.session_id(), custom_id);

        // Drop the session (simulating completion - this closes the receiver)
        drop(session1);

        // Now creating a session with the same ID should succeed since the old one is complete
        let session2 = session_manager.create_session_with_id(custom_id).await.unwrap();
        assert_eq!(session2.session_id(), custom_id);
    }

    #[tokio::test]
    async fn test_session_complete_removes_from_registry()
    {
        let session_manager = Arc::new(SessionManager::new());

        let custom_id = 55555555_u32;
        
        // Create session with custom ID
        let session = session_manager.create_session_with_id(custom_id).await.unwrap();
        assert_eq!(session.session_id(), custom_id);

        // Verify session is in the registry
        {
            let channels = session_manager.duplex_channels.read().await;
            assert!(channels.contains_key(&custom_id));
        }

        // Complete the session - this should remove it from the registry
        session.complete().await;

        // Verify session was removed from the registry
        {
            let channels = session_manager.duplex_channels.read().await;
            assert!(!channels.contains_key(&custom_id));
        }
    }
}