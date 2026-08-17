//! PAP authentication execution for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_agent_client::{
    PapAuthenticationOperation, PapAuthenticationOperationResponse, ServiceError,
};
use tacacsrs_flows::authentication::PapAuthenticationExchange;

use super::UpstreamBridge;
use super::mapping::to_pap_authentication_response;
use super::routed::RoutedOperation;
use crate::upstream::UpstreamConnection;

struct PapAuthenticationRoute;

#[async_trait]
impl RoutedOperation for PapAuthenticationRoute {
    type Request = PapAuthenticationOperation;
    type Response = PapAuthenticationOperationResponse;

    const NAME: &'static str = "PAP authentication";
    const DISPLAY_NAME: &'static str = "PAP authentication";

    async fn send(
        connection: &dyn UpstreamConnection,
        request: Self::Request,
    ) -> anyhow::Result<Self::Response> {
        let privilege_level = u8::try_from(request.privilege_level)
            .map_err(|_| anyhow::anyhow!("PAP privilege level exceeds the TACACS+ u8 field"))?;
        let exchange = PapAuthenticationExchange::new(
            request.user,
            request.password,
            request.port,
            request.remote_address,
            privilege_level,
        );
        let reply = connection.authenticate_pap(exchange).await?;
        Ok(to_pap_authentication_response(connection.server_address(), reply))
    }
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
