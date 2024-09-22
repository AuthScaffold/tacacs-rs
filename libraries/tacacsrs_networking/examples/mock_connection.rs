
use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::{self, AccountingRequest};
use tacacsrs_messages::enumerations::*;

use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_networking::mock_connection::MockConnection;
use tacacsrs_networking::session::Session;
use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionManagementTrait;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::builder().try_init();

    #[cfg(tokio_unstable)]
    {
        console_subscriber::init();
    }

    let tacacs_connection = Arc::new(
        tacacsrs_networking::mock_connection::MockConnection::new()
    );
    tacacs_connection.run().await?;

    let session = tacacs_connection.create_session().await?;

    let accounting_request = AccountingRequest
    {
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
            "cmd=test".to_string()
        ],
    };

    let accounting_reply = AccountingReply
    {
        status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
        server_msg: "Test".to_string(),
        data: "".to_string(),
    };

    tacacs_connection.add_accounting_reply(&session, 2, &accounting_reply).await?;
    
    session.send_accounting_request(accounting_request).await?;


    Ok(())
}

#[async_trait]
pub trait MockConnectionAccountingSessionTrait
{
    async fn add_accounting_reply(self: &Arc<Self>, session: &Session, reply_sequence_number: u8, reply: &AccountingReply) -> anyhow::Result<()>;
}

#[async_trait]
impl MockConnectionAccountingSessionTrait for MockConnection
{
    async fn add_accounting_reply(self: &Arc<Self>, session: &Session, reply_sequence_number: u8, reply: &AccountingReply) -> anyhow::Result<()>
    {
        let data = reply.to_bytes();

        let accounting_reply_packet = Packet::new(Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: reply_sequence_number,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id: session.session_id(),
            length: data.len() as u32,
        }, data).unwrap();
    
        self.add_reply(accounting_reply_packet).await
    }
}

