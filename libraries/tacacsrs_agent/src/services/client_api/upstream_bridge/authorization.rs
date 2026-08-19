//! Authorization request execution for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_agent_client::{
    AuthorizationOperation, AuthorizationOperationResponse, AuthorizationResponseStatus,
    ServiceError,
};
use tacacsrs_messages::traits::TacacsBodyTrait;

use super::mapping::{build_authorization_request, to_authorization_response};
use super::UpstreamBridge;
use super::routed::RoutedOperation;
use crate::upstream::{OperationKind, UpstreamConnection, UpstreamRequestError};

struct AuthorizationRoute;

#[async_trait]
impl RoutedOperation for AuthorizationRoute {
    type Request = AuthorizationOperation;
    type Response = AuthorizationOperationResponse;

    const NAME: &'static str = "authorization";
    const DISPLAY_NAME: &'static str = "Authorization";
    const OPERATION: OperationKind = OperationKind::Authorization;
    async fn send(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> Result<Self::Response, UpstreamRequestError> {
        let request =
            build_authorization_request(request).map_err(UpstreamRequestError::invalid_request)?;
        let reply = connection.send_authorization(request).await?;
        to_authorization_response(connection.server_address(), reply)
            .map_err(UpstreamRequestError::outcome_unknown)
    }

    fn is_server_error(response: &Self::Response) -> bool {
        response.status == AuthorizationResponseStatus::Error
    }

    fn request_body_length(request: &Self::Request) -> Result<usize, UpstreamRequestError> {
        build_authorization_request(request)
            .map_err(UpstreamRequestError::invalid_request)?
            .to_bytes()
            .map(|body| body.len())
            .map_err(UpstreamRequestError::invalid_request)
    }
}

impl UpstreamBridge {
    /// Runs one IPC authorization request against the selected TACACS+ server.
    ///
    /// Authorization and accounting use the same server selection and failover
    /// model. The networking layer controls connection reuse.
    pub(in crate::services::client_api) async fn execute_authorization_request(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        self.execute_operation::<AuthorizationRoute>(request).await
    }
}
