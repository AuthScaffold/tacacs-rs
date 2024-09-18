use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;
use tacacsrs_messages::{header::Header, packet::Packet};

use tacacsrs_messages::constants::TACACS_HEADER_LENGTH;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::net::TcpStream;
use tokio::task::{self, JoinHandle};

use crate::{duplex_channel::DuplexChannel, session::Session};


#[derive(Clone)]
pub struct ConnectionInfo
{
    pub ip_socket : SocketAddr,
    pub obfuscation_key : Option<Vec<u8>>
}


pub struct Connection {
    pub duplex_channels: RwLock<HashMap<u32, mpsc::Sender<Packet>>>,
    connection_info: ConnectionInfo,

    sender: tokio::sync::mpsc::Sender<Packet>,
    receiver: Mutex<Option<tokio::sync::mpsc::Receiver<Packet>>>,

    run_task : RwLock<Option<JoinHandle<anyhow::Result<()>>>>
}


impl Connection
{
    // Setup the information required for the TCP connection,
    // but do not connect.
    pub fn new(connection_info : &ConnectionInfo) -> Self
    {
        let (sender, receiver) = mpsc::channel::<Packet>(32);

        Self
        {
            duplex_channels: HashMap::new().into(),
            connection_info: connection_info.clone(),
            sender,
            receiver: Some(receiver).into(),
            run_task : None.into()
        }
    }

    pub async fn is_running(&self) -> bool
    {
        let run_task_lock = self.run_task.read().await;
        run_task_lock.as_ref().map(|f| f.is_finished()).unwrap_or(false)
    }

    pub async fn connect(self: Arc<Self>) -> anyhow::Result<()>
    {
        let stream = TcpStream::connect(self.connection_info.ip_socket).await?;

        let self_clone = Arc::clone(&self);
        task::spawn(async move {
            self_clone.handle_connection(stream).await
        });

        Ok(())
    }

    async fn handle_connection(self: Arc<Self>, stream: TcpStream) -> anyhow::Result<()> {
        let (reader, writer) = stream.into_split();

        let write_task = {
            let self_clone = Arc::clone(&self);
            let receiver = self_clone.receiver.lock().await.take().unwrap();

            task::spawn(async move {
                Connection::write_handler(receiver, writer, self_clone.connection_info.obfuscation_key.clone()).await
            })
        };

        let read_task = {
            let self_clone = Arc::clone(&self);
            task::spawn(async move {
                self_clone.read_handler(reader).await
            })
        };

        // Wait for both tasks to complete, and return an error if either task fails.
        let (write_result, read_result) = tokio::try_join!(write_task, read_task)?;
        write_result?;
        read_result?;
        Ok(())
    }

    async fn write_handler(mut receiver : tokio::sync::mpsc::Receiver<Packet>, mut writer: tokio::net::tcp::OwnedWriteHalf, obfuscation_key : Option<Vec<u8>>) -> anyhow::Result<()> {
        loop {
            let mut packet = match receiver.recv().await {
                Some(packet) => packet,
                None => return Err(anyhow::Error::msg("No packet received"))
            };

            let is_packet_obfuscated = packet.header().flags.contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG) == false;
            packet = match &obfuscation_key {
                Some(key) => match is_packet_obfuscated {
                    true => packet,
                    false => packet.as_obfuscated(&key).ok_or(anyhow::Error::msg("Failed to obfuscate packet"))?
                },
                None => packet
            };

            let bytes = packet.to_bytes();
            writer.write_all(&bytes).await?;
        }
    }

    async fn read_handler(self: Arc<Self>, mut _reader: tokio::net::tcp::OwnedReadHalf) -> anyhow::Result<()> {
        loop {
            let mut header_buffer = [0_u8; TACACS_HEADER_LENGTH];

            match _reader.read_exact(&mut header_buffer).await {
                Ok(_) => (),
                Err(e) => return Err(anyhow::Error::msg(e.to_string()))
            };

            let header = Header::from_bytes(&header_buffer)?;

            // Always read the body, regardless of the presence of the session. This is to prevent the 
            // stream from getting out of sync.
            let mut body_buffer = Vec::with_capacity(header.length as usize);
            _reader.read_exact(&mut body_buffer).await?;

            // Create a new packet and potentially deobfuscate it.
            let mut packet = Packet::new(header, body_buffer)?;
            let is_packet_obfuscated = packet.header().flags.contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG) == false;
            packet = match &self.connection_info.obfuscation_key {
                Some(key) => match is_packet_obfuscated {
                    true => packet.as_deobfuscated(&key).ok_or(anyhow::Error::msg("Failed to obfuscate packet"))?,
                    false => packet
                },
                None => packet
            };

            // Get a read lock on the duplex_channels dictionary and 
            // find the appropriate channel to forward the packet to.
            let duplex_channels = self.duplex_channels.read().await;

            match duplex_channels.get(&packet.header().session_id) {
                Some(channel) => channel.send(packet).await?,
                None => continue
            };
        }
    }

    async fn create_channel(self: Arc<Self>) -> anyhow::Result<(DuplexChannel, u32)>
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

    pub async fn create_session(self: Arc<Self>) -> anyhow::Result<Session>
    {
        let (duplex_channel, session_id) = self.create_channel().await?;
        Ok(Session::new(session_id, duplex_channel))
    }
}