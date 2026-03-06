use std::sync::Arc;

use env_logger::Env;
use tacacsrs_flows::accounting::AccountingFlowTrait;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::*;
use tacacsrs_networking::helpers::connect_tcp;
use tacacsrs_networking::transport::tls_psk::{PskConfigurationBuilder, PskIdentity};
use tacacsrs_networking::TacacsConnection;

use tacacsrs_networking::traits::SessionManagementTrait;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();

    let hostname = "tacacsserver.local:449";
    let obfuscation_key: Option<Vec<u8>> = None;

    // Configure the PSK identity and key for TLS 1.3 out-of-band PSK.
    let psk_identity =
        PskIdentity::new("tacacs-client-01".to_string(), b"my-pre-shared-key-material".to_vec())?;

    let tcp_stream = connect_tcp(hostname).await?;

    let tls_stream = PskConfigurationBuilder::new(psk_identity)
        .with_server_name("tacacsserver.local")
        .connect(tcp_stream)
        .await?;

    let connection = Arc::new(TacacsConnection::new(obfuscation_key.as_deref()));
    connection.run(tls_stream).await?;

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
            println!("Failed to send accounting request: {}", e);
            return Err(e);
        }
    };

    println!("Received accounting response: {:#?}", response);

    Ok(())
}
