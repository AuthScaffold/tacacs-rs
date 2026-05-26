//! Authorization request execution for [`ServiceState`].

use async_trait::async_trait;
use tacacsrs_agent_client::{AuthorizationOperation, AuthorizationOperationResponse, ServiceError};
use tacacsrs_config::TacacsPlusServer;

use super::common::RoutedOperation;
use super::ServiceState;
use crate::upstream::{DedicatedOperationResult, UpstreamConnection, UpstreamConnector};

struct AuthorizationRoute;

#[async_trait]
impl RoutedOperation for AuthorizationRoute {
    type Request = AuthorizationOperation;
    type Response = AuthorizationOperationResponse;

    const NAME: &'static str = "authorization";
    const DISPLAY_NAME: &'static str = "Authorization";

    async fn send_shared(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> anyhow::Result<Self::Response> {
        connection.send_authorization(request).await
    }

    async fn send_dedicated(
        connector: &dyn UpstreamConnector,
        server: &TacacsPlusServer,
        request: &Self::Request,
    ) -> anyhow::Result<DedicatedOperationResult<Self::Response>> {
        connector
            .send_authorization_dedicated(server, request)
            .await
    }
}

impl ServiceState {
    /// Executes one IPC authorization RPC against the currently selected
    /// upstream TACACS+ server.
    ///
    /// Authorization follows the same connection strategy and failover model as
    /// accounting: dedicated one-shot connections are used until a server proves
    /// single-connection support, after which requests reuse the cached shared
    /// connection.
    pub(in crate::service) async fn execute_authorization_request(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        self.execute_operation::<AuthorizationRoute>(request).await
    }
}
