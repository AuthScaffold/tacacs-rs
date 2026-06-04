//! Accounting request execution for [`ServiceState`].

use async_trait::async_trait;
use tacacsrs_agent_client::{AccountingOperation, AccountingOperationResponse, ServiceError};

use super::common::RoutedOperation;
use super::ServiceState;
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
        request: &Self::Request,
    ) -> anyhow::Result<Self::Response> {
        connection.send_accounting(request).await
    }
}

impl ServiceState {
    /// Executes one IPC accounting RPC against the currently selected upstream
    /// TACACS+ server.
    ///
    /// Connection reuse and single-connection negotiation are handled by the
    /// networking layer behind the selected upstream connection.
    pub(in crate::service) async fn execute_accounting_request(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        self.execute_operation::<AccountingRoute>(request).await
    }
}
