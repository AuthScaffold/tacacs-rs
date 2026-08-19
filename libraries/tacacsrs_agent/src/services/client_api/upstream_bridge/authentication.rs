//! PAP authentication execution for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_agent_client::{
    AuthenticationResponseStatus, PapAuthenticationOperation, PapAuthenticationOperationResponse,
    ServiceError,
};
use tacacsrs_flows::authentication::PapAuthenticationExchange;
use tacacsrs_networking::FixedExchange;

use super::UpstreamBridge;
use super::mapping::to_pap_authentication_response;
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
        Ok(to_pap_authentication_response(connection.server_address(), reply))
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
    let privilege_level = u8::try_from(request.privilege_level).map_err(|_| {
        UpstreamRequestError::invalid_request(anyhow::anyhow!(
            "PAP privilege level exceeds the TACACS+ u8 field"
        ))
    })?;
    Ok(PapAuthenticationExchange::new(
        request.user.clone(),
        request.password.clone(),
        request.port.clone(),
        request.remote_address.clone(),
        privilege_level,
    ))
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
