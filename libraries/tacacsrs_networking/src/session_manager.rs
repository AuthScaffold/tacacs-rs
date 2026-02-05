use std::collections::HashMap;
use std::sync::Arc;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use tokio::sync::{mpsc, Mutex, Notify, RwLock};

use crate::duplex_channel::DuplexChannel;
use crate::session::Session;

/// Represents the state of single connection mode negotiation with the server.
/// 
/// TACACS+ servers may or may not support single connection mode. This is indicated
/// by the TAC_PLUS_SINGLE_CONNECT_FLAG in the response packet. Until we receive the
/// first response, we don't know if the server supports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleConnectionState {
    /// No session has been created yet. The first session can be created.
    Initial,
    /// A session has been created but we haven't received a response yet.
    /// No new sessions can be created until we receive the first response
    /// and determine if single connection mode is supported.
    Negotiating,
    /// Server supports single connection mode (TAC_PLUS_SINGLE_CONNECT_FLAG was set).
    /// Multiple sessions can be multiplexed over this connection.
    Supported,
    /// Server does not support single connection mode (TAC_PLUS_SINGLE_CONNECT_FLAG was not set).
    /// Connection should be closed after the current session completes.
    NotSupported,
}

impl Default for SingleConnectionState {
    fn default() -> Self {
        Self::Initial
    }
}

#[derive(Debug)]
pub struct SessionManager {
    pub(crate) duplex_channels: RwLock<HashMap<u32, mpsc::Sender<Packet>>>,
    pub(crate) sender: tokio::sync::mpsc::Sender<Packet>,
    pub(crate) receiver: Mutex<Option<tokio::sync::mpsc::Receiver<Packet>>>,
    
    can_accept_new_sessions: RwLock<bool>,
    
    /// Tracks whether the server supports single connection mode.
    /// Until we receive the first response packet, this is `Unknown`.
    single_connection_state: RwLock<SingleConnectionState>,
    
    /// Notifies waiters when the connection should be closed.
    /// This is triggered when the last session completes and single connection mode is not supported.
    close_notify: Notify,
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
            can_accept_new_sessions: true.into(),
            single_connection_state: SingleConnectionState::Initial.into(),
            close_notify: Notify::new(),
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
        if !*can_accept_lock {
            return false;
        }
        drop(can_accept_lock);
        
        // Check single connection state
        let state = self.single_connection_state.read().await;
        match *state {
            SingleConnectionState::NotSupported => false,
            SingleConnectionState::Supported => true,
            SingleConnectionState::Initial => true,  // First session can always be created
            SingleConnectionState::Negotiating => false,  // Must wait for negotiation to complete
        }
    }

    /// Returns the current single connection state.
    pub async fn single_connection_state(&self) -> SingleConnectionState {
        let state = self.single_connection_state.read().await;
        *state
    }

    /// Sets the single connection state based on the server's response.
    /// 
    /// This should be called when the first packet is received from the server.
    /// If `server_supports_single_connection` is false, the connection should be
    /// closed after the current session completes.
    pub async fn set_single_connection_state(&self, server_supports_single_connection: bool) {
        let mut state = self.single_connection_state.write().await;
        
        // Only update if currently Negotiating - don't change once determined
        if *state != SingleConnectionState::Negotiating {
            log::debug!(
                target: "tacacsrs_networking::session_manager::set_single_connection_state",
                "Single connection state is {:?}, ignoring update to {}",
                *state, server_supports_single_connection
            );
            return;
        }
        
        let new_state = if server_supports_single_connection {
            SingleConnectionState::Supported
        } else {
            SingleConnectionState::NotSupported
        };
        
        log::info!(
            target: "tacacsrs_networking::session_manager::set_single_connection_state",
            "Setting single connection state to {:?}",
            new_state
        );
        
        *state = new_state;
    }

    /// Marks that negotiation has started (first session created, awaiting response).
    /// Transitions from Initial -> Negotiating.
    async fn begin_negotiation(&self) {
        let mut state = self.single_connection_state.write().await;
        if *state == SingleConnectionState::Initial {
            log::debug!(
                target: "tacacsrs_networking::session_manager::begin_negotiation",
                "Transitioning from Initial to Negotiating"
            );
            *state = SingleConnectionState::Negotiating;
        }
    }

    /// Returns true if the server does not support single connection mode.
    /// This means the connection should be closed after the current session completes.
    pub async fn should_close_after_session(&self) -> bool {
        let state = self.single_connection_state.read().await;
        *state == SingleConnectionState::NotSupported
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

        // If this is the first session (state is Initial), transition to Negotiating
        self.begin_negotiation().await;

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
            
            // Check if we should signal connection close
            // (no more sessions and single connection not supported)
            if duplex_channels.is_empty() {
                drop(duplex_channels); // Release write lock before reading state
                
                if self.should_close_after_session().await {
                    log::info!(
                        target: "tacacsrs_networking::session_manager::remove_session",
                        "Last session completed and single connection mode not supported. Signaling connection close."
                    );
                    self.close_notify.notify_waiters();
                }
            }
        }
    }

    /// Waits until the connection should be closed.
    /// 
    /// This returns when the last session completes and single connection mode is not supported.
    pub async fn wait_for_close(&self) {
        self.close_notify.notified().await;
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
        
        // Create first session to move to Negotiating, then simulate server response
        let custom_id = 12345678_u32;
        let _session1 = session_manager.create_session_with_id(custom_id).await.unwrap();
        
        // Enable single connection mode so we can create multiple sessions
        session_manager.set_single_connection_state(true).await;

        // Second session with same custom ID should fail because it's still in use
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
        
        // Create first session with custom ID (moves to Negotiating)
        let session1 = session_manager.create_session_with_id(custom_id).await.unwrap();
        assert_eq!(session1.session_id(), custom_id);
        
        // Simulate server response enabling single connection mode
        session_manager.set_single_connection_state(true).await;

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

    #[tokio::test]
    async fn test_single_connection_state_starts_initial()
    {
        let session_manager = SessionManager::new();
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Initial);
    }

    #[tokio::test]
    async fn test_single_connection_state_transitions_to_negotiating()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // State should be Initial before creating any sessions
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Initial);
        
        // Create first session - should transition to Negotiating
        let _session1 = session_manager.create_session().await.unwrap();
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Negotiating);
    }

    #[tokio::test]
    async fn test_single_connection_state_supported()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // Create session to move to Negotiating state
        let _session1 = session_manager.create_session().await.unwrap();
        
        // Now set to supported (simulating server response)
        session_manager.set_single_connection_state(true).await;
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Supported);
    }

    #[tokio::test]
    async fn test_single_connection_state_not_supported()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // Create session to move to Negotiating state
        let _session1 = session_manager.create_session().await.unwrap();
        
        // Now set to not supported (simulating server response)
        session_manager.set_single_connection_state(false).await;
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::NotSupported);
    }

    #[tokio::test]
    async fn test_single_connection_state_cannot_be_changed_once_set()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // Create session and set to supported
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Supported);
        
        // Try to change to not supported - should be ignored
        session_manager.set_single_connection_state(false).await;
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Supported);
    }

    #[tokio::test]
    async fn test_cannot_create_second_session_when_negotiating()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // First session should succeed (transitions Initial -> Negotiating)
        let _session1 = session_manager.create_session().await.unwrap();
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Negotiating);
        
        // Second session should fail because we're still negotiating
        let result = session_manager.create_session().await;
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("not accepting new sessions"));
    }

    #[tokio::test]
    async fn test_can_create_multiple_sessions_when_state_supported()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // Create first session and simulate server response with single connect flag
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;
        
        // Multiple sessions should succeed when single connection is supported
        let _session2 = session_manager.create_session().await.unwrap();
        let _session3 = session_manager.create_session().await.unwrap();
    }

    #[tokio::test]
    async fn test_cannot_create_session_when_state_not_supported()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // Create first session before state is known
        let _session1 = session_manager.create_session().await.unwrap();
        
        // Set state to not supported
        session_manager.set_single_connection_state(false).await;
        
        // Cannot create new sessions when single connection is not supported
        let result = session_manager.create_session().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_should_close_after_session()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // Should not close when state is Initial
        assert!(!session_manager.should_close_after_session().await);
        
        // Create session and set to supported
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;
        
        // Should not close when state is Supported
        assert!(!session_manager.should_close_after_session().await);
    }

    #[tokio::test]
    async fn test_should_close_after_session_when_not_supported()
    {
        let session_manager = Arc::new(SessionManager::new());
        
        // Create session and set to not supported
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(false).await;
        
        // Should close when state is NotSupported
        assert!(session_manager.should_close_after_session().await);
    }
}