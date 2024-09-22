use std::collections::HashMap;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use tokio::sync::{mpsc, Mutex, RwLock};

use crate::duplex_channel::DuplexChannel;
use crate::session::Session;

#[derive(Debug)]
pub struct SessionManager {
    pub(crate) duplex_channels: RwLock<HashMap<u32, mpsc::Sender<Packet>>>,
    pub(crate) sender: tokio::sync::mpsc::Sender<Packet>,
    pub(crate) receiver: Mutex<Option<tokio::sync::mpsc::Receiver<Packet>>>,
    
    can_accept_new_sessions: RwLock<bool>
}

impl SessionManager
{
    pub(crate) fn new() -> Self
    {
        let (sender, receiver) = mpsc::channel::<Packet>(32);

        Self
        {
            duplex_channels: HashMap::new().into(),
            sender,
            receiver: Some(receiver).into(),
            can_accept_new_sessions: true.into()
        }
    }

    pub(crate) async fn disable_new_sessions(&self)
    {
        let mut can_accept_lock = self.can_accept_new_sessions.write().await;
        *can_accept_lock = false;
    }

    pub(crate) async fn create_channel(&self) -> anyhow::Result<(DuplexChannel, u32)>
    {
        // create some channel where the send side connects to the internal MPSC receiver
        // aka clone the sender and pass it to the DuplexChannel. Then create a new mpsc
        // and associate that with the session id here inside the connection.
        let (session_sender, session_receiver) = mpsc::channel::<Packet>(32);

        let duplex_channel = DuplexChannel::new(session_receiver, self.sender.clone() );

        // Generate new session id, regenerate session id if it already exists
        let mut session_id = rand::random::<u32>();

        // get lock on duplex_channels and then insert the new session id
        {
            let mut duplex_channels = self.duplex_channels.write().await;

            while duplex_channels.contains_key(&session_id)
            {
                session_id = rand::random::<u32>();
            }

            duplex_channels.insert(session_id, session_sender);
        }

        Ok((duplex_channel, session_id))
    }


    pub async fn can_create_sessions(&self) -> bool
    {
        let can_accept_lock = self.can_accept_new_sessions.read().await;
        *can_accept_lock
    }

    pub async fn create_session(&self) -> anyhow::Result<Session>
    {
        if !self.can_create_sessions().await
        {
            return Err(anyhow::Error::msg("Connection is not accepting new sessions"));
        }

        let (duplex_channel, session_id) = self.create_channel().await?;

        log::info!(
            target: "tacacsrs_networking::connection::create_session",
            "Created session with id: {}",
            session_id
        );

        Ok(Session::new(session_id, duplex_channel))
    }

    pub async fn send_message_to_session(&self, packet: Packet) -> anyhow::Result<()>
    {
        // Get a read lock on the duplex_channels dictionary and 
        // find the appropriate channel to forward the packet to.
        let duplex_channels = self.duplex_channels.read().await;
        let session_id = packet.header().session_id;

        match duplex_channels.get(&session_id) {
            Some(channel) => {
                log::info!(
                    target: "tacacsrs_networking::session_manager::send_message_to_session",
                    "Found client channel for session id {}, forwarding packet",
                    session_id
                );

                match channel.send(packet).await
                {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        log::warn!(
                            target: "tacacsrs_networking::session_manager::send_message_to_session",
                            "Failed to send packet to client channel for session id: {} due to error: {}",
                            session_id, e.to_string()
                        );

                        Err(anyhow::Error::msg("Failed to send packet to client channel"))
                    }
                }
            },
            
            None => {
                Err(anyhow::Error::msg("No client channel found for session id"))
            }
        }
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[tokio::test]
    async fn test_create_channel()
    {
        let session_manager = SessionManager::new();

        let (_, session_id) = session_manager.create_channel().await.unwrap();

        assert_ne!(session_id, 0);
    }

    #[tokio::test]
    async fn test_create_channel_with_existing_session_id()
    {
        let session_manager = SessionManager::new();

        let (_, session_id) = session_manager.create_channel().await.unwrap();
        let (_, session_id2) = session_manager.create_channel().await.unwrap();

        assert_ne!(session_id, session_id2);
    }

    #[tokio::test]
    async fn test_create_session()
    {
        let session_manager = SessionManager::new();

        let session = session_manager.create_session().await.unwrap();

        assert_ne!(session.session_id(), 0);
    }


    #[tokio::test]
    async fn test_create_session_when_connection_is_not_accepting_new_sessions()
    {
        let session_manager = SessionManager::new();

        session_manager.disable_new_sessions().await;

        let result = session_manager.create_session().await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_session_when_connection_is_not_accepting_new_sessions_and_has_existing_sessions()
    {
        let session_manager = SessionManager::new();

        // creating a session when connection is ok should succeed
        _ = session_manager.create_session().await.unwrap();

        session_manager.disable_new_sessions().await;

        // creating a session when connection is not accepting new sessions should fail
        let result = session_manager.create_session().await;

        assert!(result.is_err());
    }
}