use std::sync::Arc;
use async_trait::async_trait;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;

use tokio::net::TcpStream;

use crate::packet_reader::{PacketReader, PacketReaderTrait, PacketReadResult};
use crate::packet_writer::{PacketWriter, PacketWriterTrait};
use crate::session::Session;
use crate::traits::SessionManagementTrait;

#[async_trait]
pub trait TcpConnectionTrait: SessionManagementTrait {
    fn new(obfuscation_key: Option<&[u8]>) -> Self;
    async fn run(self: &Arc<Self>, stream: TcpStream) -> anyhow::Result<()>;
}

pub struct TcpConnection {
    connection: Arc<crate::session_manager::SessionManager>,
    packet_reader: Arc<dyn PacketReaderTrait>,
    packet_writer: Arc<dyn PacketWriterTrait>,
}

impl TcpConnection {
    async fn handle_connection(&self, stream: TcpStream) -> anyhow::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let receiver = self.connection.receiver.lock().await.take().unwrap();

        // Use async blocks with try_join! instead of spawning tasks.
        // Since both are joined before this function returns, we can borrow
        // from `self` instead of cloning Arcs into each task.
        let write_future = async {
            match self.packet_writer.run_write_loop(
                receiver,
                &mut writer,
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

    /// Creates a new `TcpConnection` with custom packet reader and writer for dependency injection.
    /// 
    /// This is useful for testing where you want to inject mock implementations.
    pub fn with_packet_handlers(
        packet_reader: Arc<dyn PacketReaderTrait>,
        packet_writer: Arc<dyn PacketWriterTrait>,
    ) -> Self {
        Self {
            connection: Arc::new(crate::session_manager::SessionManager::new()),
            packet_reader,
            packet_writer,
        }
    }

    async fn read_handler(
        &self,
        mut reader: tokio::net::tcp::OwnedReadHalf,
    ) -> anyhow::Result<()> {
        // Track locally whether we've reached the terminal NotSupported state.
        // NotSupported is terminal - once set, it won't change back.
        // However, Supported can transition to NotSupported if the server signals shutdown.
        let mut single_connection_mode_is_not_supported = false;

        loop {
            // Use select to either read the next packet or receive a close signal
            let read_result = tokio::select! {
                // Wait for close signal (triggered when last session completes and single connection not supported)
                _ = self.connection.wait_for_close() => {
                    log::info!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Received close signal. Server does not support single connection mode and all sessions complete."
                    );
                    return Ok(());
                }

                // Read the next packet using the packet reader
                result = self.packet_reader.read_packet(&mut reader) => result
            };

            let packet = match read_result {
                PacketReadResult::Success(packet) => packet,
                PacketReadResult::HeaderReadError(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to read header from network due to error: {}",
                        e
                    );
                    return Err(anyhow::Error::msg(e.to_string()));
                }
                PacketReadResult::HeaderParseError(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to parse header due to error: {}",
                        e
                    );
                    continue;
                }
                PacketReadResult::BodyReadError { session_id, error } => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to read body for session id {} due to error: {}",
                        session_id, error
                    );
                    return Err(anyhow::Error::msg(error.to_string()));
                }
                PacketReadResult::PacketCreateError { session_id, error } => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Could not load packet for session id {}. Failed with error: {}",
                        session_id, error
                    );
                    continue;
                }
            };

            // Check the single connect flag from the server's response and update our state.
            // This is critical for determining if we can multiplex sessions on this connection.
            // Skip if already NotSupported (terminal state), but keep checking if Supported
            // since server can downgrade to NotSupported to signal graceful shutdown.
            if !single_connection_mode_is_not_supported {
                let server_supports_single_connect = packet
                    .header()
                    .flags
                    .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG);
                self.connection
                    .set_single_connection_state(server_supports_single_connect)
                    .await;
                
                // Once NotSupported, it's terminal - no need to check further
                if !server_supports_single_connect {
                    single_connection_mode_is_not_supported = true;
                }
            }

            let _ = self.connection.send_message_to_session(packet).await;

            // Note: Connection close is handled via wait_for_close() in the select! above.
            // When the session completes and calls complete(), it triggers remove_session(),
            // which will notify us if single connection mode is not supported.
        }
    }
}

#[async_trait]
impl TcpConnectionTrait for TcpConnection {
    fn new(obfuscation_key: Option<&[u8]>) -> Self {
        let key = obfuscation_key.map(|k| k.to_vec());
        Self {
            connection: Arc::new(crate::session_manager::SessionManager::new()),
            packet_reader: Arc::new(PacketReader::new(key.clone())),
            packet_writer: Arc::new(PacketWriter::new(key)),
        }
    }


    async fn run(self: &Arc<Self>, stream: TcpStream) -> anyhow::Result<()> {
        self.handle_connection(stream).await
    }
}

#[async_trait]
impl SessionManagementTrait for TcpConnection {
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
