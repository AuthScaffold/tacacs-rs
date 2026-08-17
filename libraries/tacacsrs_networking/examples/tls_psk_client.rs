//! Shows how to establish a TLS 1.3 PSK connection through the public client API.

use env_logger::Env;
use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_flows::accounting::AccountingExchange;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_networking::{ConnectOptions, TacacsClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();

    let server = TacacsPlusServerBuilder::new(
        "tacacs-psk-example",
        TacacsPlusServerType::all(),
        "tacacsserver.local",
        449,
    )
    .with_tls13_epsk("tacacs-client-01", b"my-pre-shared-key-material".to_vec())
    .build();

    let connection = TacacsClient::connect(server, ConnectOptions::default()).await?;
    let response = connection
        .execute(AccountingExchange::new(AccountingRequest {
            flags: TacacsAccountingFlags::STOP,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "admin".to_string(),
            port: "test".to_string(),
            rem_address: "1.1.1.1".to_string(),
            args: vec![
                "service=shell".to_string(),
                "task_id=123".to_string(),
                "cmd=test".to_string(),
            ],
        }))
        .await?;

    println!("Accounting response: {response:#?}");

    Ok(())
}
