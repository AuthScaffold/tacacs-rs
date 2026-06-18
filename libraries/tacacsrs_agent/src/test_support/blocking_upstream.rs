//! Blocking upstream fixtures for drain and in-flight request tests.

use std::sync::Arc;

use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus,
    AuthorizationOperation, AuthorizationOperationResponse, AuthorizationResponseStatus,
};
use tacacsrs_config::TacacsPlusServer;
use tokio::sync::Notify;

use crate::upstream::{UpstreamConnection, UpstreamConnector};

#[derive(Debug)]
pub(crate) struct BlockingConnection {
    pub address: String,
    pub release: Arc<Notify>,
}

#[async_trait]
impl UpstreamConnection for BlockingConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn stop_accepting_new_sessions(&self) {}

    async fn create_raw_session(&self) -> anyhow::Result<tacacsrs_networking::ClientSession> {
        anyhow::bail!("blocking upstream {} does not implement raw proxy sessions", self.address)
    }

    async fn send_accounting(
        &self,
        _request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        self.release.notified().await;
        Ok(AccountingOperationResponse {
            server: self.address.clone(),
            status: AccountingResponseStatus::Success,
            server_message: String::new(),
            data: String::new(),
        })
    }

    async fn send_authorization(
        &self,
        _request: &AuthorizationOperation,
    ) -> anyhow::Result<AuthorizationOperationResponse> {
        self.release.notified().await;
        Ok(AuthorizationOperationResponse {
            server: self.address.clone(),
            status: AuthorizationResponseStatus::PassAdd,
            server_message: String::new(),
            args: Vec::new(),
            data: String::new(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct BlockingConnector {
    pub connection: Arc<BlockingConnection>,
}

#[async_trait]
impl UpstreamConnector for BlockingConnector {
    async fn connect(
        &self,
        _server: &TacacsPlusServer,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        Ok(Arc::clone(&self.connection) as Arc<dyn UpstreamConnection>)
    }
}
