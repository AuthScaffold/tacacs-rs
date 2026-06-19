//! Authorization request execution for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_agent_client::{AuthorizationOperation, AuthorizationOperationResponse, ServiceError};

use super::mapping::{build_authorization_request, to_authorization_response};
use super::UpstreamBridge;
use super::routed::RoutedOperation;
use crate::upstream::UpstreamConnection;

struct AuthorizationRoute;

#[async_trait]
impl RoutedOperation for AuthorizationRoute {
    type Request = AuthorizationOperation;
    type Response = AuthorizationOperationResponse;

    const NAME: &'static str = "authorization";
    const DISPLAY_NAME: &'static str = "Authorization";

    async fn send(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> anyhow::Result<Self::Response> {
        let reply = connection
            .send_authorization(build_authorization_request(request)?)
            .await?;
        to_authorization_response(connection.server_address(), reply)
    }
}

impl UpstreamBridge {
    /// Executes one IPC authorization RPC against the currently selected
    /// upstream TACACS+ server.
    ///
    /// Authorization follows the same server-selection and failover model as
    /// accounting; connection reuse is handled by the networking layer.
    pub(in crate::services::client_api) async fn execute_authorization_request(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        self.execute_operation::<AuthorizationRoute>(request).await
    }
}
