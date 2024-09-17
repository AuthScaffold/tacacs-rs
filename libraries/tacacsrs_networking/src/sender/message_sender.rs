use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tacacsrs_messages::enumerations::TacacsType;
use crate::sender::traits::MessageSenderTrait;
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_messages::packet::Packet;

use crate::sessions::Session;



pub struct AsyncSessionBasedMessageSender
{
    //sender: tokio::sync::mpsc::Sender<Packet>,
    //receiver: tokio::sync::mpsc::Receiver<Packet>,

    session_manager : crate::session_manager::SessionManager
}

impl AsyncSessionBasedMessageSender
{
    pub fn new() -> Self
    {
        Self
        {
            session_manager: crate::session_manager::SessionManager::new()
        }
    }

    pub fn create_session(&mut self, tacacs_type : TacacsType) -> anyhow::Result<Arc<Session>>
    {
        self.session_manager.create_session(tacacs_type)
    }
}

#[async_trait]
impl MessageSenderTrait for AsyncSessionBasedMessageSender
{
    async fn send(&self, _request : &dyn TacacsBodyTrait) -> anyhow::Result<Box<dyn TacacsBodyTrait>>
    {
        unimplemented!("Implement me!")
    }
}