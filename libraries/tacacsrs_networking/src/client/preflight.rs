//! Configured connection preflight and single-connection discovery.
//!
//! When accounting-watchdog preflight is enabled, [`TacacsClient`] sends one
//! WATCHDOG accounting request during construction. For a single-connection
//! server, that request doubles as capability discovery: a server that echoes the
//! single-connect flag promotes the preflight transport into the shared cache.

use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType,
};
use tacacsrs_protocol::exchange::accounting::AccountingExchange;

use crate::establish::ConnectPreflight;

use super::TacacsClient;

impl TacacsClient {
    pub(super) async fn run_preflight(&self) -> anyhow::Result<()> {
        match self.endpoint.options.preflight() {
            ConnectPreflight::Disabled => Ok(()),
            ConnectPreflight::AccountingWatchdog => self.send_accounting_watchdog_preflight().await,
        }
    }

    async fn send_accounting_watchdog_preflight(&self) -> anyhow::Result<()> {
        let mut observation = self.endpoint.counters().watchdog_preflight();
        let reply = self
            .execute(&AccountingExchange::new(accounting_watchdog_preflight_request())?)
            .await?;

        match reply.status {
            TacacsAccountingStatus::TacPlusAcctStatusSuccess => {
                observation.succeeded = true;
                Ok(())
            }
            status => anyhow::bail!("TACACS+ accounting WATCHDOG preflight failed: {status:?}"),
        }
    }
}

pub(super) fn accounting_watchdog_preflight_request() -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::WATCHDOG,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNotSet,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: "tacacsrs-preflight".to_owned(),
        port: "tacacsrs-networking".to_owned(),
        rem_address: "127.0.0.1".to_owned(),
        args: vec![
            "task_id=tacacsrs-preflight-watchdog".to_owned(),
            "service=tacacsrs-networking".to_owned(),
            "preflight=true".to_owned(),
            "watchdog=true".to_owned(),
        ],
    }
}
