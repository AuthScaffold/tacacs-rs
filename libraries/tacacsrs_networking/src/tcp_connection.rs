
use std::sync::Arc;
use async_trait::async_trait;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;
use tacacsrs_messages::{header::Header, packet::Packet};

use tacacsrs_messages::constants::TACACS_HEADER_LENGTH;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::task;

use crate::session::Session;
use crate::traits::SessionManagementTrait;

#[async_trait]
pub trait TcpConnectionTrait : SessionManagementTrait
{
    fn new(obfuscation_key : Option<&[u8]>) -> Self;
    async fn run(self: &Arc<Self>, stream : TcpStream) -> anyhow::Result<()>;
}

pub struct TcpConnection
{
    connection : crate::session_manager::SessionManager,
    obfuscation_key : Option<Vec<u8>>,
}

impl TcpConnection
{
    async fn handle_connection(self: Arc<Self>, stream: TcpStream) -> anyhow::Result<()> {
        let (reader, writer) = stream.into_split();

        let write_task = {
            let self_clone = Arc::clone(&self);
            let receiver = self_clone.connection.receiver.lock().await.take().unwrap();

            task::spawn(async move {
                match TcpConnection::write_handler(receiver, writer, self_clone.obfuscation_key.clone()).await
                {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        log::error!(
                            target: "tacacsrs_networking::connection::handle_connection",
                            "Write task failed with error: {}",
                            e.to_string()
                        );

                        Err(e)
                    }
                }
            })
        };

        let read_task = {
            let self_clone = Arc::clone(&self);
            task::spawn(async move {
                match self_clone.read_handler(reader).await {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        log::error!(
                            target: "tacacsrs_networking::connection::handle_connection",
                            "Read task failed with error: {}",
                            e.to_string()
                        );

                        Err(e)
                    }
                }
            })
        };

        // Wait for both tasks to complete, and return an error if either task fails.
        let (write_result, read_result) = tokio::try_join!(write_task, read_task)?;

        // Set the can_accept_new_sessions flag to false, as the connection is now closed.
        self.connection.disable_new_sessions().await;

        // Bubble up any errors that occurred during the tasks.
        write_result?;
        read_result?;

        // Return Ok if both tasks completed successfully.
        Ok(())
    }

    async fn write_handler(mut receiver : tokio::sync::mpsc::Receiver<Packet>, mut writer: tokio::net::tcp::OwnedWriteHalf, obfuscation_key : Option<Vec<u8>>) -> anyhow::Result<()> {
        loop {
            let mut packet = match receiver.recv().await {
                Some(packet) => packet,
                None => {
                    log::error!(
                        target: "tacacsrs_networking::connection::write_handler",
                        "No packet received from channel"
                    );

                    return Err(anyhow::Error::msg("No packet received"))
                }
            };

            let session_id = packet.header().session_id;

            log::info!(
                target: "tacacsrs_networking::connection::write_handler",
                "Received packet for session id {} to send to network",
                session_id
            );

            let is_packet_deobfuscated = packet.header().flags.contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
            let mut did_obfuscate = false;
            packet = match &obfuscation_key {
                Some(key) => match is_packet_deobfuscated {
                    true => {
                        did_obfuscate = true;
                        packet.to_obfuscated(key)
                    },
                    false => packet
                },
                None => packet
            };

            if did_obfuscate {
                log::info!(
                    target: "tacacsrs_networking::connection::write_handler",
                    "Obfuscated packet for session id {}",
                    session_id
                );
            }

            let bytes = packet.to_bytes();
            
            writer.write_all(&bytes).await?;

            log::info!(
                target: "tacacsrs_networking::connection::write_handler",
                "Sent packet for session id {} to network",
                session_id
            );
        }
    }

    async fn read_handler(self: Arc<Self>, mut _reader: tokio::net::tcp::OwnedReadHalf) -> anyhow::Result<()> {
        loop {
            let mut header_buffer = [0_u8; TACACS_HEADER_LENGTH];

            match _reader.read_exact(&mut header_buffer).await {
                Ok(_) => (),
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to read header from network due to error: {}",
                        e.to_string()
                    );
                    return Err(anyhow::Error::msg(e.to_string()))
                }
            };

            let header = match Header::from_bytes(&header_buffer) {
                Ok(header) => header,
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to parse header due to error: {}",
                        e.to_string()
                    );

                    continue
                }
            };

            let session_id = header.session_id;

            log::info!(
                target: "tacacsrs_networking::connection::read_handler",
                "Received header with session id: {}. Loading body of length {}",
                session_id, header.length
            );

            // Always read the body, regardless of the presence of the session. This is to prevent the 
            // stream from getting out of sync.
            let mut body_buffer = vec![0_u8; header.length as usize];
            match _reader.read_exact(&mut body_buffer).await {
                Ok(_) => (),
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to {} bytes from network for body session id {} due to error: {}",
                        header.length, session_id, e.to_string()
                    );

                    return Err(anyhow::Error::msg(e.to_string()))
                }
            };

            log::info!(
                target: "tacacsrs_networking::connection::read_handler",
                "Received body for session id: {}",
                session_id
            );

            // Create a new packet and potentially deobfuscate it.
            let mut packet =  match Packet::new(header, body_buffer) {
                Ok(packet) => packet,
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Could not load packet for session id {}. Failed with error: {}",
                        session_id, e.to_string()
                    );

                    continue
                }
            };

            let is_packet_deobfuscated = packet.header().flags.contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
            let mut did_deobfuscate = false;
            packet = match &self.obfuscation_key {
                Some(key) => match is_packet_deobfuscated {
                    true => packet,
                    false => {
                        did_deobfuscate = true;
                        packet.to_deobfuscated(key)
                    },
                },
                None => packet
            };

            if did_deobfuscate {
                log::info!(
                    target: "tacacsrs_networking::connection::read_handler",
                    "Deobfuscated packet for session id: {}",
                    session_id
                );
            }

            let _ = self.connection.send_message_to_session(packet).await;
        }
    }
}

#[async_trait]
impl TcpConnectionTrait for TcpConnection
{
    fn new(obfuscation_key : Option<&[u8]>) -> Self
    {
        Self
        {
            connection: crate::session_manager::SessionManager::new(),
            obfuscation_key: obfuscation_key.map(|key| key.to_vec())
        }
    }


    async fn run(self: &Arc<Self>, stream : TcpStream) -> anyhow::Result<()>
    {
        let self_clone = Arc::clone(self);
        task::spawn(async move {
            self_clone.handle_connection(stream).await
        });

        Ok(())
    }
}

#[async_trait]
impl SessionManagementTrait for TcpConnection
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
