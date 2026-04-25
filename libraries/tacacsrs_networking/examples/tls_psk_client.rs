//! Demonstrates establishing a TLS 1.3 PSK connection by constructing a
//! [`TacacsPlusServer`] with [`TacacsPlusServerBuilder`] and letting the
//! dispatcher in [`tacacsrs_networking::config_connect`] pick the correct
//! transport.
//!
//! This is the only supported entry point for PSK connection construction —
//! the lower-level builders inside `transport::tls_psk` are crate-internal.

use std::sync::Arc;

use env_logger::Env;
use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerExt, TacacsPlusServerType};
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_networking::TacacsConnection;
use tacacsrs_networking::config_connect::{ConnectOptions, establish_stream};
use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionManagementTrait;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();

    // Configure a TACACS+ server that uses a TLS 1.3 externally provisioned PSK.
    let server = TacacsPlusServerBuilder::new(
        "tacacs-psk-example",
        TacacsPlusServerType::all(),
        "tacacsserver.local",
        449,
    )
    .with_tls13_epsk("tacacs-client-01", b"my-pre-shared-key-material".to_vec())
    .build();

    let options = ConnectOptions::default();

    let stream = establish_stream(&server, &options).await?;
    let obfuscation_key = server.obfuscation_key();
    let connection = Arc::new(TacacsConnection::new(obfuscation_key.as_deref()));
    connection.run(stream).await?;

    let session = connection.create_session().await?;

    let response = match session
        .send_accounting_request(AccountingRequest {
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
        })
        .await
    {
        Ok(response) => response,
        Err(e) => {
            println!("Failed to send accounting request: {e}");
            return Err(e);
        }
    };

    println!("Received accounting response: {response:#?}");

    Ok(())
}
