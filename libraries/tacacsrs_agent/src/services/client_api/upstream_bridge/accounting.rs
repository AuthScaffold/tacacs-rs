//! Accounting request execution for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_agent_client::{AccountingOperation, AccountingOperationResponse, ServiceError};

use super::mapping::{build_accounting_request, to_accounting_response};
use super::UpstreamBridge;
use super::routed::RoutedOperation;
use crate::upstream::UpstreamConnection;

struct AccountingRoute;

#[async_trait]
impl RoutedOperation for AccountingRoute {
    type Request = AccountingOperation;
    type Response = AccountingOperationResponse;

    const NAME: &'static str = "accounting";
    const DISPLAY_NAME: &'static str = "Accounting";

    async fn send(
        connection: &dyn UpstreamConnection,
        request: Self::Request,
    ) -> anyhow::Result<Self::Response> {
        let reply = connection
            .send_accounting(build_accounting_request(&request))
            .await?;
        Ok(to_accounting_response(connection.server_address(), reply))
    }
}

impl UpstreamBridge {
    /// Runs one IPC accounting request against the selected TACACS+ server.
    ///
    /// The networking layer controls connection reuse and single-connection
    /// negotiation.
    pub(in crate::services::client_api) async fn execute_accounting_request(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        self.execute_operation::<AccountingRoute>(request).await
    }
}
