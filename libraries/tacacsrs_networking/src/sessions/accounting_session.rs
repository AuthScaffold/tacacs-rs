use async_trait::async_trait;
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

use crate::session::Session;
use std::sync::Arc;
use tacacsrs_messages::accounting::{request::AccountingRequest, reply::AccountingReply};
use tacacsrs_messages::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};

#[async_trait]
pub trait AccountingSessionTrait {
    async fn send_accounting_request(self : Arc<Self>, request: AccountingRequest) -> anyhow::Result<AccountingReply>;
}

#[async_trait]
impl AccountingSessionTrait for Session {
    async fn send_accounting_request(self : Arc<Self>, request: AccountingRequest) -> anyhow::Result<AccountingReply>
    {
        let sequence_number = {
            let mut sequence_number_lock = self.outgoing_sequence_number.write().await;
            let sequence_number = *sequence_number_lock;
            *sequence_number_lock = sequence_number.wrapping_add(1);

            sequence_number
        };

        let data = request.to_bytes();

        let packet = Packet::new(Header {
            major_version : TacacsMajorVersion::TacacsPlusMajor1,
            minor_version : TacacsMinorVersion::TacacsPlusMinorVerOne,
            tacacs_type : TacacsType::TacPlusAccounting,
            seq_no : sequence_number,
            flags : TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id : self.session_id(),
            length : data.len() as u32
        }, data)?;
        
        self.duplex_channel.sender.send(packet).await?;

        // Setup a reader lock to receive the response, it needs to be mutable so that we can call recv on it
        // therefore we need to use write() instead of read()
        let mut reader_lock = self.duplex_channel.receiver.write().await;

        let response = match reader_lock.recv().await {
            Some(response) => response,
            None => return Err(anyhow::Error::msg("Failed to receive response"))
        };

        let reply = AccountingReply::from_bytes(response.body())?;

        Ok(reply)
    }
}
