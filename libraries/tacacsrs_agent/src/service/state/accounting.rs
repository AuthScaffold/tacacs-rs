//! Accounting request execution for [`ServiceState`].

use async_trait::async_trait;
use tacacsrs_agent_client::{AccountingOperation, AccountingOperationResponse, ServiceError};
use tacacsrs_config::TacacsPlusServer;

use super::common::RoutedOperation;
use super::ServiceState;
use crate::upstream::{DedicatedOperationResult, UpstreamConnection, UpstreamConnector};

struct AccountingRoute;

#[async_trait]
impl RoutedOperation for AccountingRoute {
    type Request = AccountingOperation;
    type Response = AccountingOperationResponse;

    const NAME: &'static str = "accounting";
    const DISPLAY_NAME: &'static str = "Accounting";

    async fn send_shared(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> anyhow::Result<Self::Response> {
        connection.send_accounting(request).await
    }

    async fn send_dedicated(
        connector: &dyn UpstreamConnector,
        server: &TacacsPlusServer,
        request: &Self::Request,
    ) -> anyhow::Result<DedicatedOperationResult<Self::Response>> {
        connector.send_accounting_dedicated(server, request).await
    }
}

impl ServiceState {
    /// Executes one IPC accounting RPC against the currently selected upstream
    /// TACACS+ server.
    ///
    /// # Connection strategy
    ///
    /// By default every request gets its own dedicated short-lived TCP
    /// connection (the safe path for servers that do not support
    /// single-connection mode).
    ///
    /// Once a server proves it supports single-connection mode
    /// ([`SingleConnectionState::Supported`]), future requests multiplex
    /// sessions over a shared cached connection.  The server may later
    /// withdraw that support (e.g. for traffic-shifting), in which case the
    /// service reverts to dedicated connections.
    pub(in crate::service) async fn execute_accounting_request(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        self.execute_operation::<AccountingRoute>(request).await
    }
}
