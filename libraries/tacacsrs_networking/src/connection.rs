//! Generic connection handler for TACACS+ protocol.
//!
//! This module provides a transport-agnostic connection handler that manages
//! the lifecycle of TACACS+ sessions over any transport implementing the
//! [`Transport`] trait.
//!
//! # Architecture
//!
//! The connection handler separates concerns:
//! - **Transport**: The underlying stream (TCP, TLS, etc.) - see [`transport`](crate::transport)
//! - **Session Management**: Creating and tracking sessions - see [`SessionManager`]
//! - **Packet I/O**: Reading and writing packets - see [`PacketReaderTrait`] and [`PacketWriterTrait`]
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use tokio::net::TcpStream;
//! use tacacsrs_networking::connection::TacacsConnection;
//! use tacacsrs_networking::traits::SessionManagementTrait;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let connection: Arc<TacacsConnection> = Arc::new(TacacsConnection::new(Some(b"secret_key")));
//! let stream = TcpStream::connect("127.0.0.1:49").await?;
//!
//! // Spawn the connection handler
//! connection.run(stream).await?;
//!
//! // Create a session
//! let session = connection.create_session().await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncRead;
use tokio::task;

use crate::packet_reader::{PacketReadResult, PacketReader, PacketReaderTrait};
use crate::packet_writer::{PacketWriter, PacketWriterTrait};
use crate::session::Session;
use crate::session_manager::SessionManager;
use crate::single_connect_tracker::{LocalSingleConnectState, SingleConnectFlag};
use crate::traits::SessionManagementTrait;
use crate::transport::Transport;

/// A generic connection handler for TACACS+ protocol.
///
/// `TacacsConnection` manages the lifecycle of a TACACS+ connection over any transport
/// that implements the [`Transport`] trait. It handles:
///
/// - Concurrent packet reading and writing
/// - Session creation and management
/// - Single-connect mode negotiation
/// - Graceful shutdown coordination
///
/// The connection is designed to be wrapped in an `Arc` and shared across tasks.
pub struct TacacsConnection {
    session_manager: Arc<SessionManager>,
    packet_reader: Arc<dyn PacketReaderTrait>,
    packet_writer: Arc<dyn PacketWriterTrait>,
}

impl TacacsConnection {
    /// Creates a new connection with an optional obfuscation key.
    ///
    /// # Arguments
    ///
    /// * `obfuscation_key` - Optional key used for TACACS+ packet obfuscation.
    ///   If `None`, packets are sent in cleartext (not recommended for production).
    ///
    /// # Example
    ///
    /// ```
    /// use tacacsrs_networking::connection::TacacsConnection;
    ///
    /// // With obfuscation
    /// let conn = TacacsConnection::new(Some(b"my_secret_key"));
    ///
    /// // Without obfuscation (cleartext)
    /// let conn = TacacsConnection::new(None);
    /// ```
    #[must_use]
    pub fn new(obfuscation_key: Option<&[u8]>) -> Self {
        let key = obfuscation_key.map(<[u8]>::to_vec);
        Self {
            session_manager: Arc::new(SessionManager::new()),
            packet_reader: Arc::new(PacketReader::new(key.clone())),
            packet_writer: Arc::new(PacketWriter::new(key)),
        }
    }

    /// Creates a new connection with custom packet handlers for dependency injection.
    ///
    /// This is primarily useful for testing where you want to inject mock
    /// implementations of the packet reader and writer.
    ///
    /// # Arguments
    ///
    /// * `packet_reader` - Custom packet reader implementation
    /// * `packet_writer` - Custom packet writer implementation
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::Arc;
    /// use tacacsrs_networking::connection::TacacsConnection;
    /// use tacacsrs_networking::{PacketReader, PacketWriter};
    ///
    /// let reader = Arc::new(PacketReader::new(None));
    /// let writer = Arc::new(PacketWriter::new(None));
    /// let conn = TacacsConnection::with_packet_handlers(reader, writer);
    /// ```
    pub fn with_packet_handlers(
        packet_reader: Arc<dyn PacketReaderTrait>,
        packet_writer: Arc<dyn PacketWriterTrait>,
    ) -> Self {
        Self {
            session_manager: Arc::new(SessionManager::new()),
            packet_reader,
            packet_writer,
        }
    }

    /// Starts the connection handler for the given transport.
    ///
    /// This spawns a background task that handles packet reading and writing.
    /// The task will continue running until:
    /// - The connection is closed by the remote peer
    /// - An unrecoverable error occurs
    /// - All sessions complete and single-connect mode is not supported
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport stream (TCP, TLS, etc.)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` after spawning the handler task. Errors from the handler
    /// task are logged but not propagated.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use tokio::net::TcpStream;
    /// use tacacsrs_networking::connection::TacacsConnection;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let connection = Arc::new(TacacsConnection::new(Some(b"secret")));
    /// let stream = TcpStream::connect("127.0.0.1:49").await?;
    /// connection.run(stream).await?;
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    /// Returns an error if the transport handler task fails to spawn.
    #[allow(clippy::unused_async)]
    pub async fn run<T: Transport>(self: &Arc<Self>, transport: T) -> anyhow::Result<()> {
        let self_clone = Arc::clone(self);
        task::spawn(async move { self_clone.handle_connection(transport).await });
        Ok(())
    }

    /// Internal handler for the connection lifecycle.
    ///
    /// Splits the transport into read/write halves and runs concurrent
    /// read and write loops using `try_join!`.
    async fn handle_connection<T: Transport>(&self, transport: T) -> anyhow::Result<()> {
        let (mut reader, mut writer) = transport.split();
        let receiver = self.session_manager.receiver.lock().await.take().unwrap();

        // Use async blocks with try_join! instead of spawning tasks.
        // Since both are joined before this function returns, we can borrow
        // from `self` instead of cloning Arcs into each task.
        let write_future = async {
            match self
                .packet_writer
                .run_write_loop(receiver, &mut writer, Arc::clone(&self.session_manager))
                .await
            {
                Ok(()) => Ok(()),
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::handle_connection",
                        "Write task failed with error: {e}"
                    );
                    Err(e)
                }
            }
        };

        let read_future = async {
            match self.read_handler(&mut reader).await {
                Ok(()) => Ok(()),
                Err(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::handle_connection",
                        "Read task failed with error: {e}"
                    );

                    Err(e)
                }
            }
        };

        // Wait for both futures to complete concurrently.
        // try_join! returns Ok only if both succeed, propagating the first error otherwise.
        let result = tokio::try_join!(write_future, read_future);

        // Always disable new sessions when the connection ends, regardless of success or failure.
        // This ensures the session manager won't accept new sessions on a closed/failed connection.
        self.session_manager.disable_new_sessions().await;

        // Close all sessions so that any outstanding sessions
        // will stop awaiting for network responses
        self.session_manager.close_all_sessions().await;

        result?;
        Ok(())
    }

    /// Internal read handler loop.
    ///
    /// Continuously reads packets from the transport and dispatches them to
    /// the appropriate session. Also handles single-connect mode negotiation.
    async fn read_handler<R: AsyncRead + Unpin + Send>(
        &self,
        reader: &mut R,
    ) -> anyhow::Result<()> {
        let mut local_state = LocalSingleConnectState::default();

        loop {
            // Use select to either read the next packet or receive a close signal
            let read_result = tokio::select! {
                // Wait for close signal (triggered when last session completes and single connection not supported)
                () = self.session_manager.wait_for_close() => {
                    log::info!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Received close signal. Server does not support single connection mode and all sessions complete."
                    );
                    return Ok(());
                }

                // Read the next packet using the packet reader
                result = self.packet_reader.read_packet(reader) => result
            };

            let packet = match read_result {
                PacketReadResult::Success(packet) => packet,
                PacketReadResult::HeaderReadError(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to read header from network due to error: {e}"
                    );
                    return Err(anyhow::Error::msg(e.to_string()));
                }
                PacketReadResult::HeaderParseError(e) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to parse header due to error: {e}"
                    );
                    continue;
                }
                PacketReadResult::BodyLengthExceeded {
                    session_id,
                    body_length,
                    max_length,
                } => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Rejecting packet for session id {session_id} with excessive body length {body_length} (max allowed: {max_length}). Closing connection to prevent stream desynchronization."
                    );
                    return Err(anyhow::Error::msg(format!(
                        "Packet body length {body_length} exceeds maximum allowed {max_length}"
                    )));
                }
                PacketReadResult::BodyReadError { session_id, error } => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Failed to read body for session id {session_id} due to error: {error}"
                    );
                    return Err(anyhow::Error::msg(error.to_string()));
                }
                PacketReadResult::PacketCreateError { session_id, error } => {
                    log::error!(
                        target: "tacacsrs_networking::connection::read_handler",
                        "Could not load packet for session id {session_id}. Failed with error: {error}"
                    );
                    continue;
                }
            };

            // Update single connection state based on the TAC_PLUS_SINGLE_CONNECT_FLAG.
            // Only notify the session manager on state transitions.
            let flag = SingleConnectFlag::from_packet(&packet);
            local_state = local_state
                .process_packet(flag, &self.session_manager)
                .await;

            let _ = self.session_manager.send_message_to_session(packet).await;

            // Note: Connection close is handled via wait_for_close() in the select! above.
            // When the session completes and calls complete(), it triggers remove_session(),
            // which will notify us if single connection mode is not supported.
        }
    }
}

#[async_trait]
impl SessionManagementTrait for TacacsConnection {
    async fn can_create_sessions(self: &Arc<Self>) -> bool {
        self.session_manager.can_create_sessions().await
    }

    async fn create_session(self: &Arc<Self>) -> anyhow::Result<Session> {
        self.session_manager.create_session().await
    }

    async fn create_session_with_id(self: &Arc<Self>, session_id: u32) -> anyhow::Result<Session> {
        self.session_manager
            .create_session_with_id(session_id)
            .await
    }

    async fn single_connection_state(
        self: &Arc<Self>,
    ) -> crate::session_manager::SingleConnectionState {
        self.session_manager.single_connection_state().await
    }

    async fn should_close_after_session(self: &Arc<Self>) -> bool {
        self.session_manager.should_close_after_session().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_creation() {
        let conn = TacacsConnection::new(Some(b"test_key"));
        assert!(Arc::new(conn).session_manager.receiver.try_lock().is_ok());
    }

    #[test]
    fn test_connection_without_obfuscation() {
        let conn = TacacsConnection::new(None);
        assert!(Arc::new(conn).session_manager.receiver.try_lock().is_ok());
    }
}
