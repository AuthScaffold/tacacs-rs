use std::sync::Arc;
use async_trait::async_trait;

use tokio::io::{split, ReadHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::packet_reader::{PacketReader, PacketReaderTrait, PacketReadResult};
use crate::packet_writer::{PacketWriter, PacketWriterTrait};
use crate::session::Session;
use crate::single_connect_tracker::{LocalSingleConnectState, SingleConnectFlag};
use crate::traits::SessionManagementTrait;

#[async_trait]
pub trait TLSConnectionTrait: SessionManagementTrait {
    async fn run(self: &Arc<Self>, stream: TlsStream<TcpStream>) -> anyhow::Result<()>;
}

pub struct TlsConnection {
    connection: Arc<crate::session_manager::SessionManager>,
    packet_reader: Arc<dyn PacketReaderTrait>,
    packet_writer: Arc<dyn PacketWriterTrait>,
}

impl TlsConnection {
    pub fn new(obfuscation_key: Option<&[u8]>) -> Self {
        let key = obfuscation_key.map(|k| k.to_vec());
        Self {
            connection: Arc::new(crate::session_manager::SessionManager::new()),
            packet_reader: Arc::new(PacketReader::new(key.clone())),
            packet_writer: Arc::new(PacketWriter::new(key)),
        }
    }

    /// Creates a new `TlsConnection` with custom packet reader and writer for dependency injection.
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

    async fn handle_connection(&self, stream: TlsStream<TcpStream>) -> anyhow::Result<()> {
        let (reader, mut writer) = split(stream);
        let receiver = self.connection.receiver.lock().await.take().unwrap();

        // Use async blocks with try_join! instead of spawning tasks.
        // Since both are joined before this function returns, we can borrow
        // from `self` instead of cloning Arcs into each task.
        let write_future = async {
            match self
                .packet_writer
                .run_write_loop(receiver, &mut writer, Arc::clone(&self.connection))
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
        let result = tokio::try_join!(write_future, read_future);

        // Always disable new sessions when the connection ends, regardless of success or failure.
        // This ensures the session manager won't accept new sessions on a closed/failed connection.
        self.connection.disable_new_sessions().await;

        result?;
        Ok(())
    }

    async fn read_handler(&self, mut reader: ReadHalf<TlsStream<TcpStream>>) -> anyhow::Result<()> {
        let mut local_state = LocalSingleConnectState::default();

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

            // Update single connection state based on the TAC_PLUS_SINGLE_CONNECT_FLAG.
            // Only notify the session manager on state transitions.
            let flag = SingleConnectFlag::from_packet(&packet);
            local_state = local_state.process_packet(flag, &self.connection).await;

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
