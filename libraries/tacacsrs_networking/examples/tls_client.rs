//! Demonstrates establishing a certificate-based TLS connection by
//! constructing a [`TacacsPlusServer`] with [`TacacsPlusServerBuilder`] and
//! letting the dispatcher in [`tacacsrs_networking::config_connect`] pick the
//! correct transport.
//!
//! This is the only supported entry point for TLS connection construction —
//! the lower-level builders inside `transport::tls` are crate-internal.

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

    let binary_path = std::env::current_exe()?;
    let Some(parent_folder) = binary_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
    else {
        println!("Failed to get parent folder of binary path.");
        return Err(anyhow::Error::msg("Failed to get parent folder of binary path."));
    };

    let examples_folder = parent_folder
        .join("libraries")
        .join("tacacsrs_networking")
        .join("examples");

    let client_certificate_path = examples_folder.join("samples").join("client.crt.der");
    let client_key_path = examples_folder.join("samples").join("client.key.der");

    if !client_certificate_path.exists() || !client_key_path.exists() {
        println!(
            "Client certificate {} or key {} does not exist.",
            client_certificate_path.display(),
            client_key_path.display()
        );
        return Err(anyhow::Error::msg("Client certificate or key does not exist."));
    }

    let cert_data = tokio::fs::read(&client_certificate_path).await?;
    let key_data = tokio::fs::read(&client_key_path).await?;

    let server = TacacsPlusServerBuilder::new(
        "tacacs-tls-example",
        TacacsPlusServerType::all(),
        "tacacsserver.local",
        449,
    )
    .with_tls_client_certificate(Some(cert_data), Some(key_data))
    .build();

    let options = ConnectOptions {
        disable_certificate_verification: true,
        timeout: None,
    };

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
