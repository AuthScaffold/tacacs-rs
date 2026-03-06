use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use tacacsrs_flows::accounting::AccountingFlowTrait;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::*;

use tacacsrs_messages::packet::Packet;
use tacacsrs_messages::header::Header;
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_networking::connection::TacacsConnection;
use tacacsrs_networking::transport::mock::MockTransport;
use tacacsrs_networking::session::Session;
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
        data: "".to_string(),
    };

    mock_control
        .add_accounting_reply(&session, 2, &accounting_reply)
        .await?;

    session.send_accounting_request(accounting_request).await?;


    Ok(())
}

#[async_trait]
pub trait MockConnectionAccountingSessionTrait {
    async fn add_accounting_reply(
        self: &Arc<Self>,
        session: &Session,
        reply_sequence_number: u8,
        reply: &AccountingReply,
    ) -> anyhow::Result<()>;
}

#[async_trait]
impl MockConnectionAccountingSessionTrait for MockTransport {
    async fn add_accounting_reply(
        self: &Arc<Self>,
        session: &Session,
        reply_sequence_number: u8,
        reply: &AccountingReply,
    ) -> anyhow::Result<()> {
        let data = reply.to_bytes();

        let accounting_reply_packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: reply_sequence_number,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: session.session_id(),
                length: data.len() as u32,
            },
            data,
        )
        .unwrap();

        self.coordinator().add_reply(accounting_reply_packet).await
    }
}
