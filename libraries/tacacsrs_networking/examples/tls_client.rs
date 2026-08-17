//! Shows how to establish a certificate-based TLS connection through the
//! public client API.

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
        println!("The binary path has no parent directory.");
        return Err(anyhow::Error::msg("The binary path has no parent directory"));
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
        return Err(anyhow::Error::msg("Client certificate or key does not exist"));
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

    let connection = TacacsClient::connect(
        server,
        ConnectOptions::default().with_certificate_verification_disabled(true),
    )
    .await?;
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
