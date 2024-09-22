use async_trait::async_trait;
use log::info;
use tokio::sync::RwLock;
use std::sync::Arc;
use tacacsrs_messages::{
    accounting::reply::AccountingReply,
    enumerations::*,
    header::Header,
    packet::Packet, packet::PacketTrait,
    traits::TacacsBodyTrait};

use crate::{session::Session, session_manager::SessionManager, traits::SessionManagementTrait};


#[derive(Debug)]
pub struct MockConnection {
    connection : crate::session_manager::SessionManager,
    replies : RwLock<std::collections::HashMap<u32, std::collections::HashMap<u8, tacacsrs_messages::packet::Packet>>>,
    requests : RwLock<std::collections::HashMap<u32, std::collections::HashMap<u8, tacacsrs_messages::packet::Packet>>>,
    run_task : RwLock<Option<tokio::task::JoinHandle<anyhow::Result<()>>>>
}


#[async_trait]
pub trait MockConnectionTrait
{
    fn new() -> Self;
    fn run(self : &Arc<Self>) -> anyhow::Result<()>;
    fn handle_connection(self : &Arc<Self>) -> anyhow::Result<()>;
    fn add_reply(self : &Arc<Self>, reply: tacacsrs_messages::packet::Packet) -> anyhow::Result<()>;
    async fn add_accounting_reply(self: &Arc<Self>, session: &Session, reply_sequence_number: u8, reply: &AccountingReply) -> anyhow::Result<()>;
}

impl MockConnection {
    pub fn new() -> Self {
        MockConnection {
            connection : SessionManager::new(),
            replies : std::collections::HashMap::new().into(),
            requests : std::collections::HashMap::new().into(),
            run_task : Option::None.into()
        }
    }

    pub async fn run(self : &Arc<Self>) -> anyhow::Result<()> {
        info!("Starting!");
        let self_clone = self.clone();
        let run_task_future = async move {
            let result = match self_clone.handle_connection().await{
                Ok(_) => Ok(()),
                Err(e) => {
                    info!("Handler exited with Error: {:?}", e);
                    Err(e)
                },
            };

            self_clone.connection.duplex_channels.write().await.clear();

            result
        };

        let mut run_task_lock = self.run_task.write().await;
        *run_task_lock = Some(tokio::spawn(run_task_future));

        Ok(())
    }

    async fn handle_connection(self: &Arc<Self>) -> anyhow::Result<()> {
        let mut receiver = self.connection.receiver.lock().await.take().unwrap();

        info!("Handling connection!");

        loop {
            let request = match receiver.recv().await {
                Some(request) => request,
                None => return Err(anyhow::Error::msg("Failed to receive request"))
            };

            let session_id = request.header().session_id;
            let request_sequence_number = request.header().seq_no;
            let reply_sequence_number = request.header().seq_no + 1;

            info!(
                target: "tacacsrs_networking::mock_connection",
                "Received request for session {} with sequence number {}",
                session_id,
                request_sequence_number
            );

            let mut replies = self.replies.write().await;

            let reply_list = match replies.get_mut(&session_id) {
                Some(reply_list) => reply_list,
                None => {
                    info!(
                        target: "tacacsrs_networking::mock_connection",
                        "No replies for session {}",
                        session_id
                    );
                    continue
                }
            };

            let reply = match reply_list.remove(&reply_sequence_number) {
                Some(reply) => reply,
                None => {
                    info!(
                        target: "tacacsrs_networking::mock_connection",
                        "No reply for session {} with reply sequence number {}",
                        session_id,
                        reply_sequence_number
                    );
                    continue
                }
            };

            let mut requests = self.requests.write().await;
            let request_list = requests
                .entry(request.header().session_id)
                .or_insert(std::collections::HashMap::new());
            request_list.insert(request.header().seq_no, request);

                
            match self.connection.send_message_to_session(reply).await {
                Ok(_) => {
                    info!(
                        target: "tacacsrs_networking::mock_connection",
                        "Sent reply for session {} with sequence number {}",
                        session_id,
                        reply_sequence_number
                    );
                },
                Err(e) => {
                    info!(
                        target: "tacacsrs_networking::mock_connection",
                        "Failed to send reply for session {} with sequence number {} due to error: {}",
                        session_id,
                        reply_sequence_number,
                        e.to_string()
                    );
                }
            }
        }
    }

    pub async fn add_reply(self : &Arc<Self>, reply: tacacsrs_messages::packet::Packet) -> anyhow::Result<()> {
        let mut replies = self.replies.write().await;

        let reply_list = replies
            .entry(reply.header().session_id).or_insert(std::collections::HashMap::new());


        info!(
            target: "tacacsrs_networking::mock_connection",
            "Added reply to session {} with sequence number {}",
            reply.header().session_id,
            reply.header().seq_no
        );

        reply_list.insert(reply.header().seq_no, reply);

        Ok(())
    }

    pub async fn add_accounting_reply(self: &Arc<Self>, session: &Session, reply_sequence_number: u8, reply: &AccountingReply) -> anyhow::Result<()>
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

    pub async fn get_replies_for_session(self : &Arc<Self>, session_id: u32) -> anyhow::Result<std::collections::HashMap<u8, tacacsrs_messages::packet::Packet>>
    {
        let replies = self.replies.read().await;
        
        match replies.get(&session_id)
        {
            Some(reply_list) => Ok(reply_list.clone()),
            None => Err(anyhow::Error::msg("No replies for session"))
        }
    }

    pub async fn get_requests_for_session(self : &Arc<Self>, session_id: u32) -> anyhow::Result<std::collections::HashMap<u8, tacacsrs_messages::packet::Packet>>
    {
        let requests = self.requests.read().await;
        
        match requests.get(&session_id)
        {
            Some(request_list) => Ok(request_list.clone()),
            None => Err(anyhow::Error::msg("No requests for session"))
        }
    }
}

#[async_trait]
impl SessionManagementTrait for MockConnection
{
    async fn can_create_sessions(self : &Arc<Self>) -> bool
    {
        self.connection.can_create_sessions().await
    }

    async fn create_session(self : &Arc<Self>) -> anyhow::Result<Session>
    {
        self.connection.create_session().await
    }
}

