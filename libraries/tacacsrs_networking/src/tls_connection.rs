use std::sync::Arc;
use async_trait::async_trait;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;
use tacacsrs_messages::{header::Header, packet::Packet};

use tacacsrs_messages::constants::TACACS_HEADER_LENGTH;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::session::Session;
use crate::traits::SessionManagementTrait;

#[async_trait]
pub trait TLSConnectionTrait: SessionManagementTrait {
    async fn run(self: &Arc<Self>, stream: TlsStream<TcpStream>) -> anyhow::Result<()>;
}

pub struct TlsConnection {
    connection: Arc<crate::session_manager::SessionManager>,
    obfuscation_key: Option<Vec<u8>>,
}

impl TlsConnection {
    pub fn new(obfuscation_key: Option<&[u8]>) -> Self {
        Self {
            connection: Arc::new(crate::session_manager::SessionManager::new()),
            obfuscation_key: obfuscation_key.map(|key| key.to_vec()),
        }
    }

    async fn handle_connection(&self, stream: TlsStream<TcpStream>) -> anyhow::Result<()> {
        let (reader, writer) = split(stream);
        let receiver = self.connection.receiver.lock().await.take().unwrap();

        // Use async blocks with try_join! instead of spawning tasks.
        // Since both are joined before this function returns, we can borrow
        // from `self` instead of cloning Arcs into each task.
        let write_future = async {
            match TlsConnection::write_handler(
                receiver,
                writer,
                self.obfuscation_key.clone(),
                Arc::clone(&self.connection),
            )
            .await
            {
                Ok(_) => Ok(()),
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::handle_connection",
                        "Write task failed with error: {}",
                        e
                    );
                    Err(e)
                }
            }
        };

        let read_future = async {
            match self.read_handler(reader).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::handle_connection",
                        "Read task failed with error: {}",
                        e
                    );

                    // Close all sessions so that any outstanding sessions
                    // will stop awaiting for network responses
                    self.connection.close_all_sessions().await;

                    Err(e)
                }
            }
        };

        // Wait for both futures to complete concurrently.
        // try_join! returns Ok only if both succeed, propagating the first error otherwise.
        tokio::try_join!(write_future, read_future)?;

        // Set the can_accept_new_sessions flag to false, as the connection is now closed.
        self.connection.disable_new_sessions().await;

        Ok(())
    }

    async fn write_handler(
        mut receiver: tokio::sync::mpsc::Receiver<Packet>,
        mut writer: WriteHalf<TlsStream<TcpStream>>,
        obfuscation_key: Option<Vec<u8>>,
        connection: Arc<crate::session_manager::SessionManager>,
    ) -> anyhow::Result<()> {
        loop {
            let mut packet = tokio::select! {
                // Wait for close signal
                _ = connection.wait_for_close() => {
                    log::info!(
                        target: "tacacsrs_networking::connection::write_handler",
                        "Received close signal. Shutting down write handler."
                    );
                    // Gracefully shutdown the write half
                    let _ = writer.shutdown().await;
                    return Ok(())
                }

                // Wait for packet to send
                packet = receiver.recv() => {
                    match packet {
                        Some(packet) => packet,
                        None => {
                            log::info!(
                                target: "tacacsrs_networking::connection::write_handler",
                                "Channel closed. Shutting down write handler."
                            );
                            let _ = writer.shutdown().await;
                            return Ok(())
                        }
                    }
                }
            };

            let session_id = packet.header().session_id;

            log::info!(
                target: "tacacsrs_networking::connection::write_handler",
                "Received packet for session id {} to send to network",
                session_id
            );

            let is_packet_deobfuscated = packet
                .header()
                .flags
                .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
            let mut did_obfuscate = false;
            packet = match &obfuscation_key {
                Some(key) => match is_packet_deobfuscated {
                    true => {
                        did_obfuscate = true;
                        packet.to_obfuscated(key)
                    }
                    false => packet,
                },
                None => packet,
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

    async fn read_handler(
        &self,
        mut reader: ReadHalf<TlsStream<TcpStream>>,
    ) -> anyhow::Result<()> {
        loop {
            // Use select to either read the next packet or receive a close signal
            let header_buffer = tokio::select! {
                // Wait for close signal (triggered when last session completes and single connection not supported)
                _ = self.connection.wait_for_close() => {
                    log::info!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Received close signal. Server does not support single connection mode and all sessions complete."
                    );
                    return Ok(());
                }

                // Read the next packet header
                result = async {
                    let mut header_buffer = [0_u8; TACACS_HEADER_LENGTH];
                    match reader.read_exact(&mut header_buffer).await {
                        Ok(_) => Ok(header_buffer),
                        Err(e) => Err(e)
                    }
                } => {
                    match result {
                        Ok(buf) => buf,
                        Err(e) => {
                            log::error!(
                                target: "tacacsrs_networking::connection::read_handler",
                                "Failed to read header from network due to error: {}",
                                e
                            );
                            return Err(anyhow::Error::msg(e.to_string()))
                        }
                    }
                }
            };

            let header = match Header::from_bytes(&header_buffer) {
                Ok(header) => header,
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to parse header due to error: {}",
                        e
                    );

                    continue;
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
            match reader.read_exact(&mut body_buffer).await {
                Ok(_) => (),
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to {} bytes from network for body session id {} due to error: {}",
                        header.length, session_id, e
                    );

                    return Err(anyhow::Error::msg(e.to_string()));
                }
            };

            log::info!(
                target: "tacacsrs_networking::connection::read_handler",
                "Received body for session id: {}",
                session_id
            );

            // Create a new packet and potentially deobfuscate it.
            let mut packet = match Packet::new(header, body_buffer) {
                Ok(packet) => packet,
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Could not load packet for session id {}. Failed with error: {}",
                        session_id, e
                    );

                    continue;
                }
            };

            let is_packet_deobfuscated = packet
                .header()
                .flags
                .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
            let mut did_deobfuscate = false;
            packet = match &self.obfuscation_key {
                Some(key) => match is_packet_deobfuscated {
                    true => packet,
                    false => {
                        did_deobfuscate = true;
                        packet.to_deobfuscated(key)
                    }
                },
                None => packet,
            };

            if did_deobfuscate {
                log::info!(
                    target: "tacacsrs_networking::connection::read_handler",
                    "Deobfuscated packet for session id: {}",
                    session_id
                );
            }

            // Check the single connect flag from the server's response and update our state.
            // This is critical for determining if we can multiplex sessions on this connection.
            let server_supports_single_connect = packet
                .header()
                .flags
                .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG);
            self.connection
                .set_single_connection_state(server_supports_single_connect)
                .await;

            let _ = self.connection.send_message_to_session(packet).await;

            // Note: Connection close is handled via wait_for_close() in the select! above.
            // When the session completes and calls complete(), it triggers remove_session(),
            // which will notify us if single connection mode is not supported.
        }
    }
}

#[async_trait]
impl TLSConnectionTrait for TlsConnection {
    async fn run(self: &Arc<Self>, stream: TlsStream<TcpStream>) -> anyhow::Result<()> {
        self.handle_connection(stream).await
    }
}

#[async_trait]
impl SessionManagementTrait for TlsConnection {
    async fn can_create_sessions(self: &Arc<Self>) -> bool {
        self.connection.can_create_sessions().await
    }

    async fn create_session(self: &Arc<Self>) -> anyhow::Result<Session> {
        self.connection.create_session().await
    }

    async fn create_session_with_id(self: &Arc<Self>, session_id: u32) -> anyhow::Result<Session> {
        self.connection.create_session_with_id(session_id).await
    }

    async fn single_connection_state(
        self: &Arc<Self>,
    ) -> crate::session_manager::SingleConnectionState {
        self.connection.single_connection_state().await
    }

    async fn should_close_after_session(self: &Arc<Self>) -> bool {
        self.connection.should_close_after_session().await
    }
}
