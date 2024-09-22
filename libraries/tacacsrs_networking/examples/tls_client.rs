use std::sync::Arc;

use env_logger::Env;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::*;
use tacacsrs_networking::helpers::connect_tcp;

use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionManagementTrait;
use tacacsrs_networking::tls_connection::TLSConnectionTrait;



use tacacsrs_networking::helpers::*;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();

    let binary_path = std::env::current_exe()?;
    let parent_folder = match binary_path.parent().unwrap().parent().unwrap().parent().unwrap().parent() {
        Some(folder) => folder,
        None => {
            println!("Failed to get parent folder of binary path.");
            return Err(anyhow::Error::msg("Failed to get parent folder of binary path."));
        }
    };

    let examples_folder = parent_folder.join("libraries").join("tacacsrs_networking").join("examples");
    
    let client_certificate = examples_folder.join("samples").join("client.crt");
    let client_key = examples_folder.join("samples").join("client.key");

    if !client_certificate.exists() || !client_key.exists() {
        println!("Client certificate {} or key {} does not exist.", client_certificate.display(), client_key.display());
        return Err(anyhow::Error::msg("Client certificate or key does not exist."));
    }


    let hostname = "tacacsserver.local:449";
    //let obfuscation_key = Some(b"tac_plus_key".to_vec());
    let obfuscation_key : Option<Vec::<u8>> = None;

    let tls_config = Arc::new(TlsConfigurationBuilder::new()
        .with_client_auth_cert_files(&client_certificate, &client_key).await?
        .with_certificate_verification_disabled(true)
        .build()?);

    let tcp_stream = connect_tcp(hostname).await?;
    let tls_stream = connect_tls(&tls_config, tcp_stream, "tacacsserver.local").await?;

    let connection = Arc::new(
        tacacsrs_networking::tls_connection::TlsConnection::new(obfuscation_key.as_deref())
    );
    connection.run(tls_stream).await?;

    let session = connection.create_session().await?;

    let response = match session.send_accounting_request(AccountingRequest
        {
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
                "cmd=test".to_string()
            ],
        }
    ).await {
        Ok(response) => response,
        Err(e) => {
            println!("Failed to send accounting request: {}", e);
            return Err(e);
        }
    };

    println!("Received accounting response: {:#?}", response);

    Ok(())
}