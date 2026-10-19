//! Authorization request execution for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_protocol::operations::{
    AuthorizationOperation, AuthorizationOperationResponse, AuthorizationResponseStatus,
};
use tacacsrs_protocol::failure::ServiceError;
use tacacsrs_protocol::exchange::authorization::AuthorizationExchange;

use super::UpstreamBridge;
use super::routed::RoutedOperation;
use crate::upstream::{OperationKind, UpstreamConnection, UpstreamRequestError};

struct AuthorizationRoute;

#[async_trait]
impl RoutedOperation for AuthorizationRoute {
    type Request = AuthorizationOperation;
    type Exchange = AuthorizationExchange;
    type Response = AuthorizationOperationResponse;

    const NAME: &'static str = "authorization";
    const DISPLAY_NAME: &'static str = "Authorization";
    const OPERATION: OperationKind = OperationKind::Authorization;
    async fn send<Connection: UpstreamConnection + ?Sized>(
        connection: &Connection,
        exchange: &Self::Exchange,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<Self::Response, UpstreamRequestError> {
        let reply = connection.send_authorization(exchange, deadline).await?;
        AuthorizationOperationResponse::from_reply(connection.server_address(), reply)
            .map_err(UpstreamRequestError::protocol_error)
    }

    fn is_server_error(response: &Self::Response) -> bool {
        response.status == AuthorizationResponseStatus::Error
    }

    fn prepare(request: &Self::Request) -> Result<Self::Exchange, UpstreamRequestError> {
        request
            .exchange()
            .map_err(UpstreamRequestError::invalid_request)
    }
}

impl<Connector: tacacsrs_networking::routed::EndpointConnector> UpstreamBridge<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    /// Runs one IPC authorization request against the selected TACACS+ server.
    ///
    /// Authorization and accounting use the same server selection and failover
    /// model. The networking layer controls connection reuse.
    pub(crate) async fn execute_authorization_request(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        self.execute_operation::<AuthorizationRoute>(request).await
    }
}
