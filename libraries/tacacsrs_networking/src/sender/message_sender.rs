use std::collections::HashMap;
use std::sync::{Arc, MutexGuard};

use async_trait::async_trait;
use tacacsrs_messages::enumerations::TacacsType;
use crate::sender::traits::MessageSenderTrait;
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_messages::packet::Packet;

use crate::sessions::Session;



pub struct AsyncSessionBasedMessageSender
{
    sender: tokio::sync::mpsc::Sender<Packet>,
    receiver: tokio::sync::mpsc::Receiver<Packet>,

    // mutex for modifying the sessions
    //session_lock : std::sync::Mutex<HashMap<u32, Arc<SessionEntry>>>,
    session_lock : std::sync::Mutex<u8>,
    sessions: HashMap<u32, Arc<Session>>,
}

impl AsyncSessionBasedMessageSender
{
    // pub fn new(sender: tokio::sync::mpsc::Sender<Packet>, receiver: tokio::sync::mpsc::Receiver<Packet>) -> Self
    // {
    //     Self
    //     {
    //         sender,
    //         receiver
    //     }
    // }

    pub fn create_session(&mut self, tacacs_type : TacacsType) -> anyhow::Result<Arc<Session>>
    {
        let mut session_id = rand::random::<u32>();

        let session_entry = match self.session_lock.lock() {
            Ok(mut _lock) => {
                // Regenerate session id if it already exists
                while self.sessions.contains_key(&session_id)
                {
                    session_id = rand::random::<u32>();
                };

                let session_entry = Arc::new(Session::new(session_id, tacacs_type));
                self.sessions.insert(session_id, session_entry.clone());
                session_entry
            }

            Err(err) => return Err(anyhow::Error::msg(err.to_string()))
        };
        
        Ok(session_entry)
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