use async_trait::async_trait;
use log::info;
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_messages::accounting::{request::AccountingRequest, reply::AccountingReply};
use tacacsrs_messages::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};

use crate::session::Session;

#[async_trait]
pub trait AccountingSessionTrait {
    async fn send_accounting_request(&self, request: AccountingRequest) -> anyhow::Result<AccountingReply>;
}

#[async_trait]
impl AccountingSessionTrait for Session {
    async fn send_accounting_request(&self, request: AccountingRequest) -> anyhow::Result<AccountingReply>
    {
        if self.is_complete().await {
            return Err(anyhow::Error::msg("Session is already complete"));
        }

        let sequence_number = self.next_sequence_number().await;

        let data = request.to_bytes();

        let packet = Packet::new(Header {
            major_version : TacacsMajorVersion::TacacsPlusMajor1,
            minor_version : TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type : TacacsType::TacPlusAccounting,
            seq_no : sequence_number,
            flags : TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id : self.session_id(),
            length : data.len() as u32
        }, data)?;

        info!(
            target: "tacacsrs_networking::sessions::accounting_session",
            "Sending Accounting Request with sequence number {} for session {}",
            sequence_number, self.session_id()
        );
        
        self.duplex_channel.sender.send(packet).await?;

        // Setup a reader lock to receive the response, it needs to be mutable so that we can call recv on it
        // therefore we need to use write() instead of read()
        let mut reader_lock = self.duplex_channel.receiver.write().await;

        let response = match reader_lock.recv().await {
            Some(response) => response,
            None => return Err(anyhow::Error::msg("Failed to receive response"))
        };

        let reply = AccountingReply::from_bytes(response.body())?;

        self.complete().await;

        log::info!(
            target: "tacacsrs_networking::sessions::accounting_session",
            "Received Accounting Reply. Session now complete"
        );

        Ok(reply)
    }
}






#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use tacacsrs_messages::enumerations::*;

    use crate::traits::SessionManagementTrait;
    use test_log::test;

    
    #[test(tokio::test)]
    async fn test_send_accounting_request() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let tacacs_connection = Arc::new(
            crate::mock_connection::MockConnection::new()
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
        
        let reply = session.send_accounting_request(accounting_request).await?;

        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);


        let requests = tacacs_connection.get_requests_for_session(session.session_id).await?;
        assert_eq!(requests.len(), 1, "The number of requests for the session was not as expected");

        let replies = tacacs_connection.get_replies_for_session(session.session_id).await?;
        assert_eq!(replies.len(), 0, "There was replies registered to session when they should have all been removed");
    
    
        Ok(())
    }
}
