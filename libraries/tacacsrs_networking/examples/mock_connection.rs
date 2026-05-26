use std::sync::Arc;

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationType,
    TacacsAuthenticationService, TacacsAccountingStatus, TacacsFlags, TacacsMajorVersion,
    TacacsMinorVersion, TacacsType,
};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

use tacacsrs_networking::connection::TacacsConnection;
use tacacsrs_networking::session::Session;
use tacacsrs_networking::transport::mock::MockTransport;
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

    send_accounting_request(&session, accounting_request).await?;

    Ok(())
}

async fn send_accounting_request(
    session: &Session,
    request: AccountingRequest,
) -> anyhow::Result<AccountingReply> {
    if session.is_complete().await {
        return Err(anyhow::Error::msg(
            "Cannot send accounting request: session is already complete",
        ));
    }
    let sequence_number = session.next_sequence_number().await;
    let data = request.to_bytes()?;
    let length = u32::try_from(data.len())
        .map_err(|_| anyhow::Error::msg("Accounting request payload exceeds u32 length"))?;
    let packet = Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: sequence_number,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id: session.session_id(),
            length,
        },
        data,
    )?;

    session.duplex_channel.sender.send(packet).await?;
    let mut reader_lock = session.duplex_channel.receiver.write().await;
    let response = reader_lock
        .recv()
        .await
        .ok_or_else(|| anyhow::Error::msg("Failed to receive response"))?;
    let reply = AccountingReply::from_bytes(response.body())?;
    session.complete().await;
    Ok(reply)
}
