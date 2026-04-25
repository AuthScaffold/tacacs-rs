use async_trait::async_trait;
use std::sync::Arc;
use crate::session::Session;
use crate::session_manager::SingleConnectionState;

#[async_trait]
pub trait SessionManagementTrait {
    async fn can_create_sessions(self: &Arc<Self>) -> bool;
    async fn create_session(self: &Arc<Self>) -> anyhow::Result<Session>;

    /// Creates a session with a specific session ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID is already in use.
    async fn create_session_with_id(self: &Arc<Self>, session_id: u32) -> anyhow::Result<Session>;

    /// Returns the current single connection state.
    ///
    /// This indicates whether the server supports single connection mode (session multiplexing).
    /// - `Initial`: No session created yet
    /// - `Negotiating`: First session created, waiting for server response
    /// - `Supported`: Server supports single connection mode
    /// - `NotSupported`: Server does not support single connection mode, connection should be closed after session
    async fn single_connection_state(self: &Arc<Self>) -> SingleConnectionState;

    /// Returns true if the connection should be closed after the current session completes.
    ///
    /// This is true when the server does not support single connection mode.
    async fn should_close_after_session(self: &Arc<Self>) -> bool;
}
