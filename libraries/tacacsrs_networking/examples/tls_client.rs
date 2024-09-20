use std::sync::Arc;

use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::*;
use tacacsrs_networking::helpers::connect_tcp;

use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionCreationTrait;
use tacacsrs_networking::tls_connection::TLSConnectionTrait;



use tacacsrs_networking::helpers::*;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let hostname = "tacacsserver.local";
    let obfuscation_key = Some(b"tac_plus_key".to_vec());

    let tcp_stream = connect_tcp(hostname).await?;
    let tls_stream = connect_tls(tcp_stream, hostname).await?;

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
