use async_trait::async_trait;
use std::sync::Arc;
use crate::session::Session;


#[async_trait]
pub trait SessionManagementTrait {
    async fn can_create_sessions(self : &Arc<Self>) -> bool;
    async fn create_session(self : &Arc<Self>) -> anyhow::Result<Session>;
    
    /// Creates a session with a specific session ID.
    /// 
    /// # Errors
    /// 
    /// Returns an error if the session ID is already in use.
    async fn create_session_with_id(self : &Arc<Self>, session_id: u32) -> anyhow::Result<Session>;
}