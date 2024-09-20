use async_trait::async_trait;
use std::sync::Arc;
use crate::session::Session;


#[async_trait]
pub trait SessionCreationTrait {
    async fn can_create_sessions(self : Arc<Self>) -> bool;
    async fn create_session(self : Arc<Self>) -> anyhow::Result<Session>;
    async fn is_running(self : Arc<Self>) -> bool;
}