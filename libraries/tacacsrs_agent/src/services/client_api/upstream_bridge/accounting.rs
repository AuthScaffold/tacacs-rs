//! Accounting request execution for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus, ServiceError,
};
use tacacsrs_messages::traits::TacacsBodyTrait;

use super::mapping::{build_accounting_request, to_accounting_response};
use super::UpstreamBridge;
use super::routed::RoutedOperation;
use crate::upstream::{OperationKind, UpstreamConnection, UpstreamRequestError};

struct AccountingRoute;

#[async_trait]
impl RoutedOperation for AccountingRoute {
    type Request = AccountingOperation;
    type Response = AccountingOperationResponse;

    const NAME: &'static str = "accounting";
    const DISPLAY_NAME: &'static str = "Accounting";
    const OPERATION: OperationKind = OperationKind::Accounting;
    async fn send(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> Result<Self::Response, UpstreamRequestError> {
        let reply = connection
            .send_accounting(build_accounting_request(request))
            .await?;
        Ok(to_accounting_response(connection.server_address(), reply))
    }

    fn is_server_error(response: &Self::Response) -> bool {
        response.status == AccountingResponseStatus::Error
    }

    fn request_body_length(request: &Self::Request) -> Result<usize, UpstreamRequestError> {
        build_accounting_request(request)
            .to_bytes()
            .map(|body| body.len())
            .map_err(UpstreamRequestError::invalid_request)
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
