use std::sync::Arc;

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationType,
    TacacsAuthenticationService, TacacsAccountingStatus,
};

use tacacsrs_networking::connection::TacacsConnection;
use tacacsrs_networking::transport::mock::MockTransport;
use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionManagementTrait;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::builder().try_init();

    #[cfg(tokio_unstable)]
    {
        console_subscriber::init();
    }

    let mock_transport = MockTransport::new();
    let mock_control = mock_transport.coordinator();
    let tacacs_connection = Arc::new(TacacsConnection::new(None));
    tacacs_connection.run(mock_transport).await?;

    let session = tacacs_connection.create_session().await?;

    let accounting_request = AccountingRequest {
        flags: TacacsAccountingFlags::START,
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
    };

    let accounting_reply = AccountingReply {
        status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
        server_msg: "Test".to_string(),
        data: String::new(),
    };

    mock_control
        .accounting_reply(&session, 2, &accounting_reply)
        .send()
        .await?;

    session.send_accounting_request(accounting_request).await?;

    Ok(())
}
