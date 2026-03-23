use std::collections::HashMap;
use std::sync::Arc;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use tokio::sync::{mpsc, Mutex, Notify, RwLock};

use crate::duplex_channel::DuplexChannel;
use crate::session::Session;
use crate::session_id::{ReservedSessionId, SessionIdAllocator};

#[derive(Debug)]
pub(crate) struct ActiveSessionEntry {
    sender: mpsc::Sender<Packet>,
    _reservation: ReservedSessionId,
}

/// Represents the state of single connection mode negotiation with the server.
///
/// TACACS+ servers may or may not support single connection mode. This is indicated
/// by the `TAC_PLUS_SINGLE_CONNECT_FLAG` in the response packet. Until we receive the
/// first response, we don't know if the server supports it.
///
/// ## State Transitions
/// ```text
/// Initial ──(first session created)──> Negotiating
///                                           │
///                    ┌──────────────────────┴──────────────────────┐
///                    │                                             │
///                    ▼                                             ▼
///              Supported ──(server signals shutdown)──>      NotSupported
///                                                           (terminal state)
/// ```
///
/// ## Graceful Shutdown
///
/// A server can signal graceful shutdown by removing the `TAC_PLUS_SINGLE_CONNECT_FLAG`
/// from response packets. When this happens, the client should:
/// 1. Stop creating new sessions on this connection
/// 2. Allow existing sessions to complete (drain)
/// 3. Close the connection once all sessions are done
///
/// This allows load balancers and clients to transition traffic to other servers
/// without disrupting in-flight requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SingleConnectionState {
    /// No session has been created yet. The first session can be created.
    #[default]
    Initial,
    /// A session has been created but we haven't received a response yet.
    /// No new sessions can be created until we receive the first response
    /// and determine if single connection mode is supported.
    Negotiating,
    /// Server supports single connection mode (`TAC_PLUS_SINGLE_CONNECT_FLAG` was set).
    /// Multiple sessions can be multiplexed over this connection.
    ///
    /// Note: This state can transition to `NotSupported` if the server later removes
    /// the flag to signal graceful shutdown.
    Supported,
    /// Server does not support single connection mode (`TAC_PLUS_SINGLE_CONNECT_FLAG` was not set).
    /// Connection should be closed after the current session completes.
    ///
    /// This is a terminal state - once set, it cannot change back to `Supported`.
    NotSupported,
}

#[derive(Debug)]
pub struct SessionManager {
    pub(crate) duplex_channels: RwLock<HashMap<u32, ActiveSessionEntry>>,
    pub(crate) sender: tokio::sync::mpsc::Sender<Packet>,
    pub(crate) receiver: Mutex<Option<tokio::sync::mpsc::Receiver<Packet>>>,
    session_id_allocator: Arc<SessionIdAllocator>,

    can_accept_new_sessions: RwLock<bool>,

    /// Tracks whether the server supports single connection mode.
    /// Until we receive the first response packet, this is `Unknown`.
    single_connection_state: RwLock<SingleConnectionState>,

    /// Notifies waiters when the connection should be closed.
    /// This is triggered when the last session completes and single connection mode is not supported.
    close_notify: Notify,
}

impl SessionManager {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = mpsc::channel::<Packet>(32);

        Self {
            duplex_channels: HashMap::new().into(),
            sender,
            receiver: Some(receiver).into(),
            session_id_allocator: SessionIdAllocator::new(),
            can_accept_new_sessions: true.into(),
            single_connection_state: SingleConnectionState::Initial.into(),
            close_notify: Notify::new(),
        }
    }

    pub(crate) async fn disable_new_sessions(&self) {
        let mut can_accept_lock = self.can_accept_new_sessions.write().await;
        *can_accept_lock = false;
    }

    async fn create_channel(&self) -> anyhow::Result<(DuplexChannel, u32)> {
        self.create_channel_with_optional_id(None).await
    }

    async fn create_channel_with_id(
        &self,
        session_id: u32,
    ) -> anyhow::Result<(DuplexChannel, u32)> {
        self.create_channel_with_optional_id(Some(session_id)).await
    }

    async fn create_channel_with_optional_id(
        &self,
        custom_session_id: Option<u32>,
    ) -> anyhow::Result<(DuplexChannel, u32)> {
        let reserved_session_id = if let Some(id) = custom_session_id {
            self.session_id_allocator.reserve_specific(id)?
        } else {
            self.session_id_allocator.reserve_generated()
        };
        let session_id = reserved_session_id.get();

        // Now create the channels after validation
        let (session_sender, session_receiver) = mpsc::channel::<Packet>(32);
        let duplex_channel = DuplexChannel::new(session_receiver, self.sender.clone());

        // Insert the new session
        {
            let mut duplex_channels = self.duplex_channels.write().await;
            duplex_channels.insert(
                session_id,
                ActiveSessionEntry {
                    sender: session_sender,
                    _reservation: reserved_session_id,
                },
            );
        }

        Ok((duplex_channel, session_id))
    }


    pub async fn can_create_sessions(&self) -> bool {
        let can_accept_lock = self.can_accept_new_sessions.read().await;
        if !*can_accept_lock {
            return false;
        }
        drop(can_accept_lock);

        // Check single connection state
        let state = self.single_connection_state.read().await;
        match *state {
            SingleConnectionState::NotSupported | SingleConnectionState::Negotiating => false,
            SingleConnectionState::Supported | SingleConnectionState::Initial => true,
        }
    }

    /// Returns the current single connection state.
    pub async fn single_connection_state(&self) -> SingleConnectionState {
        let state = self.single_connection_state.read().await;
        *state
    }

    /// Sets the single connection state based on the server's response.
    ///
    /// This should be called when packets are received from the server.
    ///
    /// ## State Transition Rules
    ///
    /// - `Negotiating` → `Supported` or `NotSupported` (based on flag)
    /// - `Supported` → `NotSupported` (server signals graceful shutdown)
    /// - `NotSupported` → (terminal, no transitions allowed)
    /// - `Initial` → (ignored, must go through `Negotiating` first)
    ///
    /// ## Graceful Shutdown
    ///
    /// When a server wants to gracefully shut down, it removes the
    /// `TAC_PLUS_SINGLE_CONNECT_FLAG` from response packets. This signals
    /// clients to stop sending new sessions and drain existing ones.
    /// This is treated as a signal for clients to transition traffic away
    /// from this server.
    pub async fn set_single_connection_state(&self, server_supports_single_connection: bool) {
        let mut state = self.single_connection_state.write().await;

        match *state {
            SingleConnectionState::Negotiating => {
                let new_state = if server_supports_single_connection {
                    SingleConnectionState::Supported
                } else {
                    SingleConnectionState::NotSupported
                };

                *state = new_state;
                drop(state);

                log::info!(
                    target: "tacacsrs_networking::session_manager::set_single_connection_state",
                    "Setting single connection state to {new_state:?}"
                );
            }
            SingleConnectionState::Supported if !server_supports_single_connection => {
                *state = SingleConnectionState::NotSupported;
                drop(state);

                log::info!(
                    target: "tacacsrs_networking::session_manager::set_single_connection_state",
                    "Server removed single-connect flag, transitioning to NotSupported (graceful shutdown signal)"
                );
            }
            _ => {
                let current = *state;
                drop(state);

                log::debug!(
                    target: "tacacsrs_networking::session_manager::set_single_connection_state",
                    "Single connection state is {current:?}, ignoring update to {server_supports_single_connection}",
                );
            }
        }
    }

    /// Atomically checks if sessions can be created and begins negotiation if in Initial state.
    ///
    /// This combines the check and state transition into a single atomic operation to prevent
    /// race conditions where multiple threads could pass the `can_create_sessions` check and
    /// both call `begin_negotiation` before the state transitions to Negotiating.
    ///
    /// Returns Ok(()) if a session can be created, Err if not.
    async fn try_begin_session(&self) -> anyhow::Result<()> {
        // First check if new sessions are accepted at all
        let can_accept_lock = self.can_accept_new_sessions.read().await;
        if !*can_accept_lock {
            return Err(anyhow::Error::msg("Connection is not accepting new sessions"));
        }
        drop(can_accept_lock);

        // Now atomically check state and transition if needed
        let mut state = self.single_connection_state.write().await;
        match *state {
            SingleConnectionState::NotSupported | SingleConnectionState::Negotiating => {
                Err(anyhow::Error::msg("Connection is not accepting new sessions"))
            }
            SingleConnectionState::Initial => {
                // Transition to Negotiating atomically within the same lock scope
                log::debug!(
                    target: "tacacsrs_networking::session_manager::try_begin_session",
                    "Transitioning from Initial to Negotiating"
                );
                *state = SingleConnectionState::Negotiating;
                Ok(())
            }
            SingleConnectionState::Supported => Ok(()),
        }
    }

    /// Returns true if the server does not support single connection mode.
    /// This means the connection should be closed after the current session completes.
    pub async fn should_close_after_session(&self) -> bool {
        let state = self.single_connection_state.read().await;
        *state == SingleConnectionState::NotSupported
    }

    /// # Errors
    /// Returns an error if the connection is not accepting new sessions.
    pub async fn create_session(self: &Arc<Self>) -> anyhow::Result<Session> {
        self.create_session_with_optional_id(None).await
    }

    /// # Errors
    /// Returns an error if the connection is not accepting new sessions or
    /// the given session ID is already in use.
    pub async fn create_session_with_id(
        self: &Arc<Self>,
        session_id: u32,
    ) -> anyhow::Result<Session> {
        self.create_session_with_optional_id(Some(session_id)).await
    }

    async fn create_session_with_optional_id(
        self: &Arc<Self>,
        custom_session_id: Option<u32>,
    ) -> anyhow::Result<Session> {
        // Atomically check if we can create sessions and begin negotiation if in Initial state
        self.try_begin_session().await?;

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

    pub async fn remove_session(&self, session_id: u32) {
        let mut duplex_channels = self.duplex_channels.write().await;
        if duplex_channels.remove(&session_id).is_some() {
            log::info!(
                target: "tacacsrs_networking::session_manager::remove_session",
                "Removed session {session_id} from duplex_channels registry"
            );

            // Check if we should signal connection close
            // (no more sessions and single connection not supported)
            // We must hold the duplex_channels lock while checking to prevent a race
            // where a new session could be created between checking emptiness and signaling close.
            if duplex_channels.is_empty() {
                let state = self.single_connection_state.read().await;
                let should_close = *state == SingleConnectionState::NotSupported;
                drop(state);
                drop(duplex_channels);

                if should_close {
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

    /// Closes all sessions by clearing the `duplex_channels` registry.
    /// This will cause any sessions waiting on channel receivers to receive None,
    /// allowing them to terminate gracefully.
    pub async fn close_all_sessions(&self) {
        let mut duplex_channels = self.duplex_channels.write().await;
        let session_count = duplex_channels.len();
        duplex_channels.clear();
        drop(duplex_channels);

        log::info!(
            target: "tacacsrs_networking::session_manager::close_all_sessions",
            "Closed all {session_count} sessions from duplex_channels registry"
        );
    }

    /// # Errors
    /// Returns an error if the session is not found in the registry.
    pub async fn send_message_to_session(&self, packet: Packet) -> anyhow::Result<()> {
        // Get a read lock on the duplex_channels dictionary and
        // find the appropriate channel to forward the packet to.
        let duplex_channels = self.duplex_channels.read().await;
        let session_id = packet.header().session_id;

        match duplex_channels.get(&session_id) {
            Some(entry) => {
                log::info!(
                    target: "tacacsrs_networking::session_manager::send_message_to_session",
                    "Found client channel for session id {session_id}, forwarding packet"
                );

                match entry.sender.send(packet).await {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        log::warn!(
                            target: "tacacsrs_networking::session_manager::send_message_to_session",
                            "Failed to send packet to client channel for session id: {session_id} due to error: {e}"
                        );

                        Err(anyhow::Error::msg("Failed to send packet to client channel"))
                    }
                }
            }

            None => Err(anyhow::Error::msg("No client channel found for session id")),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_channel() {
        let session_manager = SessionManager::new();

        let (_, session_id) = session_manager.create_channel().await.unwrap();

        assert_ne!(session_id, 0);
    }

    #[tokio::test]
    async fn test_create_channel_with_existing_session_id() {
        let session_manager = SessionManager::new();

        let (_, session_id) = session_manager.create_channel().await.unwrap();
        let (_, session_id2) = session_manager.create_channel().await.unwrap();

        assert_ne!(session_id, session_id2);
    }

    #[tokio::test]
    async fn test_create_session() {
        let session_manager = Arc::new(SessionManager::new());

        let session = session_manager.create_session().await.unwrap();

        assert_ne!(session.session_id(), 0);
    }


    #[tokio::test]
    async fn test_create_session_when_connection_is_not_accepting_new_sessions() {
        let session_manager = Arc::new(SessionManager::new());

        session_manager.disable_new_sessions().await;

        let result = session_manager.create_session().await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_session_when_connection_is_not_accepting_new_sessions_and_has_existing_sessions(
    ) {
        let session_manager = Arc::new(SessionManager::new());

        // creating a session when connection is ok should succeed
        _ = session_manager.create_session().await.unwrap();

        session_manager.disable_new_sessions().await;

        // creating a session when connection is not accepting new sessions should fail
        let result = session_manager.create_session().await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_session_with_custom_id() {
        let session_manager = Arc::new(SessionManager::new());

        let custom_id = 12_345_678_u32;
        let session = session_manager
            .create_session_with_id(custom_id)
            .await
            .unwrap();

        assert_eq!(session.session_id(), custom_id);
    }

    #[tokio::test]
    async fn test_create_session_with_duplicate_custom_id_fails() {
        let session_manager = Arc::new(SessionManager::new());

        // Create first session to move to Negotiating, then simulate server response
        let custom_id = 12_345_678_u32;
        let _session1 = session_manager
            .create_session_with_id(custom_id)
            .await
            .unwrap();

        // Enable single connection mode so we can create multiple sessions
        session_manager.set_single_connection_state(true).await;

        // Second session with same custom ID should fail because it's still in use
        let result = session_manager.create_session_with_id(custom_id).await;

        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("already in use"),
            "Expected 'already in use' error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_create_channel_with_custom_id() {
        let session_manager = SessionManager::new();

        let custom_id = 87_654_321_u32;
        let (_, session_id) = session_manager
            .create_channel_with_id(custom_id)
            .await
            .unwrap();

        assert_eq!(session_id, custom_id);
    }

    #[tokio::test]
    async fn test_create_session_with_same_id_after_completion() {
        let session_manager = Arc::new(SessionManager::new());

        let custom_id = 99_999_999_u32;

        // Create first session with custom ID (moves to Negotiating)
        let session1 = session_manager
            .create_session_with_id(custom_id)
            .await
            .unwrap();
        assert_eq!(session1.session_id(), custom_id);

        // Simulate server response enabling single connection mode
        session_manager.set_single_connection_state(true).await;

        // Mark the session complete so the manager removes it from the registry.
        session1.complete().await;

        // Now creating a session with the same ID should succeed since the old one is complete
        let session2 = session_manager
            .create_session_with_id(custom_id)
            .await
            .unwrap();
        assert_eq!(session2.session_id(), custom_id);
    }

    #[tokio::test]
    async fn test_session_complete_removes_from_registry() {
        let session_manager = Arc::new(SessionManager::new());

        let custom_id = 55_555_555_u32;

        // Create session with custom ID
        let session = session_manager
            .create_session_with_id(custom_id)
            .await
            .unwrap();
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
    async fn test_single_connection_state_starts_initial() {
        let session_manager = SessionManager::new();
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Initial);
    }

    #[tokio::test]
    async fn test_single_connection_state_transitions_to_negotiating() {
        let session_manager = Arc::new(SessionManager::new());

        // State should be Initial before creating any sessions
        assert_eq!(session_manager.single_connection_state().await, SingleConnectionState::Initial);

        // Create first session - should transition to Negotiating
        let _session1 = session_manager.create_session().await.unwrap();
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::Negotiating
        );
    }

    #[tokio::test]
    async fn test_single_connection_state_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create session to move to Negotiating state
        let _session1 = session_manager.create_session().await.unwrap();

        // Now set to supported (simulating server response)
        session_manager.set_single_connection_state(true).await;
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::Supported
        );
    }

    #[tokio::test]
    async fn test_single_connection_state_not_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create session to move to Negotiating state
        let _session1 = session_manager.create_session().await.unwrap();

        // Now set to not supported (simulating server response)
        session_manager.set_single_connection_state(false).await;
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::NotSupported
        );
    }

    #[tokio::test]
    async fn test_single_connection_state_cannot_transition_from_not_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create session and set to not supported
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(false).await;
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::NotSupported
        );

        // Try to change back to supported - should be ignored (NotSupported is terminal)
        session_manager.set_single_connection_state(true).await;
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::NotSupported
        );
    }

    /// Tests that a server can signal graceful shutdown by removing the single-connect flag.
    ///
    /// When a server wants to drain connections (e.g., for maintenance or shutdown),
    /// it removes the `TAC_PLUS_SINGLE_CONNECT_FLAG` from response packets. This signals
    /// clients to:
    /// 1. Stop creating new sessions on this connection
    /// 2. Allow existing sessions to complete
    /// 3. Close the connection and transition traffic to other servers
    #[tokio::test]
    async fn test_server_can_signal_graceful_shutdown_by_removing_single_connect_flag() {
        let session_manager = Arc::new(SessionManager::new());

        // Create session and set to supported (normal operation)
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::Supported
        );

        // Server can create more sessions while Supported
        assert!(session_manager.can_create_sessions().await);

        // Server signals graceful shutdown by removing the flag
        session_manager.set_single_connection_state(false).await;

        // State should transition to NotSupported
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::NotSupported
        );

        // No new sessions should be allowed (traffic should transition away)
        assert!(!session_manager.can_create_sessions().await);

        // should_close_after_session should now return true
        assert!(session_manager.should_close_after_session().await);
    }

    /// Tests that the Supported state remains Supported when server keeps sending the flag.
    ///
    /// This ensures we don't unnecessarily log or process updates when the server
    /// continues to support single connection mode.
    #[tokio::test]
    async fn test_supported_state_remains_supported_when_flag_still_set() {
        let session_manager = Arc::new(SessionManager::new());

        // Create session and set to supported
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::Supported
        );

        // Multiple packets with flag set should keep state as Supported
        session_manager.set_single_connection_state(true).await;
        session_manager.set_single_connection_state(true).await;
        session_manager.set_single_connection_state(true).await;

        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::Supported
        );
    }

    /// Tests the graceful shutdown flow end-to-end.
    ///
    /// Simulates a server that initially supports single connection, then signals
    /// shutdown. Verifies that:
    /// 1. New sessions are blocked after shutdown signal
    /// 2. Existing sessions can complete
    /// 3. Close is signaled after last session completes
    #[tokio::test]
    async fn test_graceful_shutdown_drains_existing_sessions() {
        use tokio::time::{timeout, Duration};

        let session_manager = Arc::new(SessionManager::new());

        // Establish connection with single-connect support
        let session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;

        // Create additional session while supported
        let session2 = session_manager.create_session().await.unwrap();

        // Server signals graceful shutdown
        session_manager.set_single_connection_state(false).await;

        // New sessions should be blocked
        let result = session_manager.create_session().await;
        assert!(result.is_err(), "New sessions should be blocked after shutdown signal");

        // Set up close waiter
        let sm_for_waiter = Arc::clone(&session_manager);
        let waiter = tokio::spawn(async move {
            timeout(Duration::from_millis(500), sm_for_waiter.wait_for_close()).await
        });

        // Complete first session - close should NOT be signaled yet
        session1.complete().await;

        // Give a moment for any premature close signal
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Session2 still exists, so verify it's in the registry
        let session_count = session_manager.duplex_channels.read().await.len();
        assert_eq!(session_count, 1, "Session2 should still be active");

        // Complete second session - NOW close should be signaled
        session2.complete().await;

        // Waiter should receive the close signal
        let result = waiter.await.unwrap();
        assert!(result.is_ok(), "Close should be signaled after all sessions drain");
    }

    #[tokio::test]
    async fn test_cannot_create_second_session_when_negotiating() {
        let session_manager = Arc::new(SessionManager::new());

        // First session should succeed (transitions Initial -> Negotiating)
        let _session1 = session_manager.create_session().await.unwrap();
        assert_eq!(
            session_manager.single_connection_state().await,
            SingleConnectionState::Negotiating
        );

        // Second session should fail because we're still negotiating
        let result = session_manager.create_session().await;
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("not accepting new sessions"));
    }

    #[tokio::test]
    async fn test_can_create_multiple_sessions_when_state_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create first session and simulate server response with single connect flag
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;

        // Multiple sessions should succeed when single connection is supported
        let _session2 = session_manager.create_session().await.unwrap();
        let _session3 = session_manager.create_session().await.unwrap();
    }

    #[tokio::test]
    async fn test_cannot_create_session_when_state_not_supported() {
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
    async fn test_should_close_after_session() {
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
    async fn test_should_close_after_session_when_not_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create session and set to not supported
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(false).await;

        // Should close when state is NotSupported
        assert!(session_manager.should_close_after_session().await);
    }

    /// Test that concurrent session creation from Initial state only allows one session.
    ///
    /// This tests the fix for the race condition where multiple threads could pass
    /// the `can_create_sessions()` check when state is Initial, and both call `begin_negotiation()`,
    /// potentially creating multiple sessions before state transitions to Negotiating.
    #[tokio::test]
    async fn test_concurrent_session_creation_from_initial_state() {
        // Run multiple iterations to increase the chance of catching race conditions
        for _ in 0..100 {
            let session_manager = Arc::new(SessionManager::new());

            // Spawn multiple tasks that all try to create a session simultaneously
            let mut handles = Vec::new();
            for _ in 0..10 {
                let sm = Arc::clone(&session_manager);
                handles.push(tokio::spawn(async move { sm.create_session().await }));
            }

            // Wait for all tasks to complete
            let results: Vec<_> = futures::future::join_all(handles)
                .await
                .into_iter()
                .map(|r| r.unwrap())
                .collect();

            // Exactly one session should succeed (transitioning Initial -> Negotiating)
            // All others should fail because state is Negotiating
            let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
            let failures: Vec<_> = results.iter().filter(|r| r.is_err()).collect();

            assert_eq!(
                successes.len(),
                1,
                "Expected exactly 1 successful session creation, got {}. \
                 This indicates a race condition where multiple threads created sessions \
                 before state transitioned to Negotiating.",
                successes.len()
            );
            assert_eq!(
                failures.len(),
                9,
                "Expected 9 failed session creations, got {}",
                failures.len()
            );

            // Verify state is Negotiating (not Initial, which would indicate the fix didn't work)
            assert_eq!(
                session_manager.single_connection_state().await,
                SingleConnectionState::Negotiating,
                "State should be Negotiating after first session creation"
            );
        }
    }

    /// Test that concurrent session creation works correctly when state is Supported.
    ///
    /// Unlike the Initial state test, all concurrent creations should succeed when
    /// single connection mode is supported.
    #[tokio::test]
    async fn test_concurrent_session_creation_when_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create first session and enable single connection mode
        let _session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;

        // Spawn multiple tasks that all try to create sessions simultaneously
        let mut handles = Vec::new();
        for _ in 0..10 {
            let sm = Arc::clone(&session_manager);
            handles.push(tokio::spawn(async move { sm.create_session().await }));
        }

        // Wait for all tasks to complete
        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // All sessions should succeed when single connection is supported
        let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
        assert_eq!(
            successes.len(),
            10,
            "All session creations should succeed when state is Supported, got {} successes",
            successes.len()
        );
    }

    /// Test that `remove_session` and `create_session` don't race on close notification.
    ///
    /// This tests the fix for the race condition where after removing the last session
    /// and before checking `should_close_after_session()`, a new session could be created,
    /// making the `duplex_channels.is_empty()` check stale.
    #[tokio::test]
    async fn test_remove_session_and_create_session_no_race_on_close() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::time::{timeout, Duration};

        // Run multiple iterations to increase the chance of catching race conditions
        for iteration in 0..50 {
            let session_manager = Arc::new(SessionManager::new());
            let close_notifications = Arc::new(AtomicUsize::new(0));

            // Create first session and set state to NotSupported
            // This means closing the last session should trigger close notification
            let session1 = session_manager.create_session().await.unwrap();
            session_manager.set_single_connection_state(true).await;

            // Set up a waiter for close notification
            let sm_for_waiter = Arc::clone(&session_manager);
            let close_count = Arc::clone(&close_notifications);
            let waiter_handle = tokio::spawn(async move {
                // Use a timeout to avoid hanging forever if close is never signaled
                if timeout(Duration::from_millis(100), sm_for_waiter.wait_for_close())
                    .await
                    .is_ok()
                {
                    close_count.fetch_add(1, Ordering::SeqCst);
                }
            });

            // Now change state to NotSupported so completing sessions could trigger close
            {
                let mut state = session_manager.single_connection_state.write().await;
                *state = SingleConnectionState::NotSupported;
            }

            // Spawn task to complete the session
            let sm_for_complete = Arc::clone(&session_manager);
            let session_id = session1.session_id();
            let complete_handle = tokio::spawn(async move {
                drop(session1); // This calls complete() which calls remove_session
                sm_for_complete.remove_session(session_id).await;
            });

            // Wait for completion
            complete_handle.await.unwrap();

            // Give the waiter a moment to process
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Cancel the waiter if it's still waiting
            waiter_handle.abort();
            let _ = waiter_handle.await;

            // Verify the close was notified (since state is NotSupported and no sessions remain)
            let notifications = close_notifications.load(Ordering::SeqCst);

            // Check current session count
            let session_count = session_manager.duplex_channels.read().await.len();

            // If no sessions remain and state is NotSupported, close should have been notified
            if session_count == 0 {
                assert_eq!(
                    notifications, 1,
                    "Iteration {iteration}: Close should have been notified exactly once when last session \
                     completes and state is NotSupported. Got {notifications} notifications."
                );
            }
        }
    }

    /// Test that close notification only happens when truly the last session completes.
    ///
    /// This verifies that if sessions are being created while another is being removed,
    /// the close notification doesn't fire prematurely.
    #[tokio::test]
    async fn test_close_not_signaled_while_sessions_exist() {
        let session_manager = Arc::new(SessionManager::new());

        // Create first session and set state to Supported so we can create multiple
        let session1 = session_manager.create_session().await.unwrap();
        session_manager.set_single_connection_state(true).await;

        // Create a second session
        let _session2 = session_manager.create_session().await.unwrap();

        // Now change state to NotSupported to test close behavior
        {
            let mut state = session_manager.single_connection_state.write().await;
            *state = SingleConnectionState::NotSupported;
        }

        // Set up a waiter that should NOT receive notification
        let sm_for_waiter = Arc::clone(&session_manager);
        let waiter_handle = tokio::spawn(async move {
            tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                sm_for_waiter.wait_for_close(),
            )
            .await
        });

        // Complete session1 - but session2 still exists, so close should NOT be signaled
        session1.complete().await;

        // Wait for the timeout
        let result = waiter_handle.await.unwrap();

        // The wait should have timed out (Err) because close should not be signaled
        // while session2 still exists
        assert!(result.is_err(), "Close should NOT be signaled while sessions still exist");

        // Verify session2 is still in the registry
        let session_count = session_manager.duplex_channels.read().await.len();
        assert_eq!(session_count, 1, "Session2 should still be in the registry");
    }
}
