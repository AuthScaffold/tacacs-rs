//! PAP authentication execution for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_protocol::operations::{
    AuthenticationResponseStatus, PapAuthenticationOperation, PapAuthenticationOperationResponse,
    ServiceError,
};
use tacacsrs_protocol::exchange::authentication::PapAuthenticationExchange;
use tacacsrs_protocol::exchange::FixedExchange;

use super::UpstreamBridge;
use super::routed::RoutedOperation;
use crate::upstream::{OperationKind, UpstreamConnection, UpstreamRequestError};

struct PapAuthenticationRoute;

#[async_trait]
impl RoutedOperation for PapAuthenticationRoute {
    type Request = PapAuthenticationOperation;
    type Response = PapAuthenticationOperationResponse;

    const NAME: &'static str = "PAP authentication";
    const DISPLAY_NAME: &'static str = "PAP authentication";
    const OPERATION: OperationKind = OperationKind::Authentication;
    async fn send(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> Result<Self::Response, UpstreamRequestError> {
        let exchange = pap_exchange(request)?;
        let reply = connection.authenticate_pap(exchange).await?;
        PapAuthenticationOperationResponse::from_reply(connection.server_address(), reply)
            .map_err(UpstreamRequestError::outcome_unknown)
    }

    fn is_server_error(response: &Self::Response) -> bool {
        response.status == AuthenticationResponseStatus::Error
    }

    fn request_body_length(request: &Self::Request) -> Result<usize, UpstreamRequestError> {
        pap_exchange(request)?
            .encode_request()
            .map(|body| body.len())
            .map_err(UpstreamRequestError::invalid_request)
    }
}

fn pap_exchange(
    request: &PapAuthenticationOperation,
) -> Result<PapAuthenticationExchange, UpstreamRequestError> {
    request
        .exchange()
        .map_err(UpstreamRequestError::invalid_request)
}

impl UpstreamBridge {
    pub(in crate::services::client_api) async fn execute_pap_authentication_request(
        &self,
        request: PapAuthenticationOperation,
    ) -> Result<PapAuthenticationOperationResponse, ServiceError> {
        self.execute_operation::<PapAuthenticationRoute>(request)
            .await
    }
}
