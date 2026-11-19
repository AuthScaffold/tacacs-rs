//! RFC 8907 accounting WATCHDOG probe for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_protocol::exchange::accounting::AccountingExchange;
use tacacsrs_protocol::failure::ServiceError;
use tacacsrs_protocol::operations::{AccountingOperationResponse, AccountingResponseStatus};

use super::UpstreamBridge;
use super::routed::RoutedOperation;
use crate::upstream::{OperationKind, UpstreamConnection, UpstreamRequestError};

/// Request marker for one upstream WATCHDOG probe.
pub(crate) struct WatchdogProbe;

struct WatchdogRoute;

#[async_trait]
impl RoutedOperation for WatchdogRoute {
    type Request = WatchdogProbe;
    type Exchange = AccountingExchange;
    type Response = AccountingOperationResponse;

    const NAME: &'static str = "accounting watchdog";
    const DISPLAY_NAME: &'static str = "Accounting watchdog";
    const OPERATION: OperationKind = OperationKind::Accounting;
    const SIDE_EFFECT_FREE_PROBE: bool = true;

    async fn send<Connection: UpstreamConnection + ?Sized>(
        connection: &Connection,
        exchange: &Self::Exchange,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<Self::Response, UpstreamRequestError> {
        let reply = connection.send_accounting(exchange, deadline).await?;
        Ok(AccountingOperationResponse::from_reply(connection.server_address(), reply))
    }

    fn is_server_error(response: &Self::Response) -> bool {
        response.status != AccountingResponseStatus::Success
    }

    fn prepare(_request: &Self::Request) -> Result<Self::Exchange, UpstreamRequestError> {
        AccountingExchange::new(watchdog_request()).map_err(UpstreamRequestError::invalid_request)
    }
}

/// Builds the WATCHDOG record. It names the agent and carries no user data.
fn watchdog_request() -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::WATCHDOG,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNotSet,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: "tacacsrs-agent".to_owned(),
        port: "tacacsrs-agent".to_owned(),
        rem_address: "127.0.0.1".to_owned(),
        args: vec![
            "task_id=tacacsrs-agent-watchdog".to_owned(),
            "service=tacacsrs-agent".to_owned(),
            "watchdog=true".to_owned(),
        ],
    }
}

impl<Connector: tacacsrs_networking::routed::EndpointConnector> UpstreamBridge<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    /// Returns whether the active server set has a server eligible for accounting.
    pub(crate) fn has_accounting_server(&self) -> bool {
        self.router.eligible_server_count(OperationKind::Accounting) > 0
    }

    /// Sends one WATCHDOG record through normal server selection.
    ///
    /// The probe skips client admission. It tries each eligible accounting
    /// server until one returns success, independent of the failover strategy.
    /// A reply other than success, a send failure, and an unknown outcome all
    /// move the probe to the next server.
    pub(crate) async fn execute_watchdog_probe(
        &self,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        self.execute_operation::<WatchdogRoute>(WatchdogProbe).await
    }
}
