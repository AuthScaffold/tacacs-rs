use std::collections::HashMap;
use tacacsrs_messages::packet::Packet;

use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::duplex_channel::DuplexChannel;
use crate::session::Session;


pub struct Connection {
    pub(crate) duplex_channels: RwLock<HashMap<u32, mpsc::Sender<Packet>>>,
    pub(crate) sender: tokio::sync::mpsc::Sender<Packet>,
    pub(crate) receiver: Mutex<Option<tokio::sync::mpsc::Receiver<Packet>>>,
    pub(crate) run_task : RwLock<Option<JoinHandle<anyhow::Result<()>>>>,
    
    can_accept_new_sessions: RwLock<bool>
}

impl Connection
{
    pub(crate) fn new() -> Self
    {
        let (sender, receiver) = mpsc::channel::<Packet>(32);

        Self
        {
            duplex_channels: HashMap::new().into(),
            sender,
            receiver: Some(receiver).into(),
            run_task : None.into(),
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

    pub async fn is_running(&self) -> bool
    {
        let run_task_lock = self.run_task.read().await;
        run_task_lock.as_ref().map(|f| f.is_finished()).unwrap_or(false)
    }
}


