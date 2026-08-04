//! Multiplexed TACACS+ packet connection runtime.
//!
//! This module drives a confirmed single-connection transport and manages the
//! lifecycle of multiple TACACS+ sessions over it.
//!
//! # Architecture
//!
//! The connection handler separates concerns:
//! - **Transport**: The underlying stream (TCP, TLS, etc.) - see [`transport`](crate::transport)
//! - **Session Management**: Creating and tracking sessions inside this module
//! - **Packet I/O**: Reading and writing packets - see [`PacketReader`] and [`PacketWriter`]
//!
//! This module is crate-private. External callers should create
//! [`TacacsClient`](crate::TacacsClient) and run higher-level
//! flows over the returned session object.

use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task;

use crate::codec::{PacketReadResult, PacketReader, PacketWriter};

mod write_loop;

use crate::single_connect::{LocalSingleConnectState, SingleConnectFlag, SingleConnectionState};
use crate::session::{PacketDispatchError, SessionManager, SharedSession};

use self::write_loop::run_write_loop;

/// A multiplexed TACACS+ connection runtime.
///
/// `MultiplexedConnection` manages the lifecycle of many TACACS+ sessions over
/// one transport. It handles:
///
/// - Concurrent packet reading and writing
/// - Session creation and management
/// - Single-connect mode negotiation
/// - Graceful shutdown coordination
///
/// The connection is designed to be wrapped in an `Arc` and shared across tasks.
pub(crate) struct MultiplexedConnection {
    session_manager: Arc<SessionManager>,
    packet_reader: PacketReader,
    packet_writer: PacketWriter,
}

impl MultiplexedConnection {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(obfuscation_key: Option<&[u8]>) -> Self {
        let key = obfuscation_key.map(<[u8]>::to_vec);
        Self {
            session_manager: Arc::new(SessionManager::new()),
            packet_reader: PacketReader::new(key.clone()),
            packet_writer: PacketWriter::new(key),
        }
    }

    /// Creates a connection whose single-connect support has already been confirmed.
    ///
    /// Use this when taking over a stream from a dedicated probe exchange that
    /// received `TAC_PLUS_SINGLE_CONNECT_FLAG` from the server.
    #[must_use]
    pub(crate) fn new_single_connect_confirmed(obfuscation_key: Option<&[u8]>) -> Self {
        let key = obfuscation_key.map(<[u8]>::to_vec);
        Self {
            session_manager: Arc::new(SessionManager::with_state(SingleConnectionState::Supported)),
            packet_reader: PacketReader::new(key.clone()),
            packet_writer: PacketWriter::new(key),
        }
    }

    pub(crate) fn run_with_halves<R, W>(self: &Arc<Self>, reader: R, writer: W)
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let self_clone = Arc::clone(self);
        task::spawn(async move {
            self_clone
                .handle_connection_with_halves(reader, writer)
                .await
        });
    }

    async fn handle_connection_with_halves<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        self.handle_connection_halves(&mut reader, &mut writer)
            .await
    }

    async fn handle_connection_halves<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let receiver = self
            .session_manager
            .take_receiver()
            .await
            .context("multiplexed TACACS+ connection runtime has already been started")?;

        let write_future = async {
            match run_write_loop(
                &self.packet_writer,
                receiver,
                writer,
                Arc::clone(&self.session_manager),
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(error) => {
                    log::error!(
                        target: "tacacsrs_networking::runtime::multiplexed::handle_connection",
                        "Write task failed with error: {error}"
                    );
                    Err(error)
                }
            }
        };

        let read_future = async {
            match self.read_handler(reader).await {
                Ok(()) => Ok(()),
                Err(error) => {
                    log::error!(
                        target: "tacacsrs_networking::runtime::multiplexed::handle_connection",
                        "Read task failed with error: {error}"
                    );

                    Err(error)
                }
            }
        };

        let result = tokio::try_join!(write_future, read_future);

        self.session_manager.disable_new_sessions().await;
        self.session_manager.close_all_sessions().await;

        result?;
        Ok(())
    }

    /// Internal read handler loop.
    ///
    /// Continuously reads packets from the transport and dispatches them to
    /// the appropriate session. Also handles single-connect mode negotiation.
    ///
    /// ```text
    /// confirmed shared connection starts as Supported
    ///     |
    ///     v
    /// read server packet
    ///     |
    ///     +-- flag set -----> keep accepting shared sessions
    ///     |
    ///     +-- flag absent --> mark NotSupported
    ///                         stop new sessions
    ///                         drain active sessions
    ///                         close shared stream
    ///
    /// transport EOF or read error
    ///     |
    ///     v
    /// runtime disables new sessions and closes active sessions
    ///     |
    ///     v
    /// owning TacacsClient clears the cache on the next create_session
    /// and renegotiates unless the connection state is already NotSupported
    /// ```
    async fn read_handler<R: AsyncRead + Unpin + Send>(
        &self,
        reader: &mut R,
    ) -> anyhow::Result<()> {
        let mut local_state = LocalSingleConnectState::default();

        loop {
            let read_result = tokio::select! {
                () = self.session_manager.wait_for_close() => {
                    log::info!(
                        target: "tacacsrs_networking::runtime::multiplexed::read_handler",
                        "Received close signal. Server does not support single connection mode and all sessions complete."
                    );
                    return Ok(());
                }

                result = self.packet_reader.read_packet(reader) => result
            };

            let packet = match read_result {
                PacketReadResult::Success(packet) => packet,
                PacketReadResult::HeaderReadError(error) => {
                    log::error!(
                        target: "tacacsrs_networking::runtime::multiplexed::read_handler",
                        "Failed to read header from network due to error: {error}"
                    );
                    return Err(error).context("failed to read TACACS+ packet header");
                }
                PacketReadResult::HeaderParseError(error) => {
                    log::error!(
                        target: "tacacsrs_networking::runtime::multiplexed::read_handler",
                        "Failed to parse header due to error: {error}"
                    );
                    return Err(error).context("failed to parse TACACS+ packet header");
                }
                PacketReadResult::BodyLengthExceeded {
                    session_id,
                    body_length,
                    max_length,
                } => {
                    log::error!(
                        target: "tacacsrs_networking::runtime::multiplexed::read_handler",
                        "Rejecting packet for session id {session_id} with excessive body length {body_length} (max allowed: {max_length}). Closing connection to prevent stream desynchronization."
                    );
                    return Err(anyhow::Error::msg(format!(
                        "Packet body length {body_length} exceeds maximum allowed {max_length}"
                    )));
                }
                PacketReadResult::BodyReadError { session_id, error } => {
                    log::error!(
                        target: "tacacsrs_networking::runtime::multiplexed::read_handler",
                        "Failed to read body for session id {session_id} due to error: {error}"
                    );
                    return Err(error).context("failed to read TACACS+ packet body");
                }
                PacketReadResult::PacketCreateError { session_id, error } => {
                    log::error!(
                        target: "tacacsrs_networking::runtime::multiplexed::read_handler",
                        "Could not load packet for session id {session_id}. Failed with error: {error}"
                    );
                    continue;
                }
            };

            let flag = SingleConnectFlag::from_packet(&packet);
            local_state = local_state
                .process_packet(flag, &self.session_manager)
                .await;

            match self.session_manager.send_message_to_session(packet).await {
                Ok(()) => {}
                Err(
                    PacketDispatchError::UnknownSession(_) | PacketDispatchError::SessionClosed(_),
                ) => {
                    log::debug!(
                        target: "tacacsrs_networking::runtime::multiplexed::read_handler",
                        "Ignoring response for a session that is no longer active"
                    );
                }
                Err(error @ PacketDispatchError::ProtocolViolation { .. }) => {
                    return Err(error.into());
                }
            }
        }
    }

    pub(crate) async fn can_create_sessions(self: &Arc<Self>) -> bool {
        self.session_manager.can_create_sessions().await
    }

    pub(crate) async fn disable_new_sessions(self: &Arc<Self>) {
        self.session_manager.disable_new_sessions().await;
    }

    pub(crate) async fn create_session(self: &Arc<Self>) -> anyhow::Result<SharedSession> {
        self.session_manager.create_session().await
    }

    pub(crate) async fn single_connection_state(self: &Arc<Self>) -> SingleConnectionState {
        self.session_manager.single_connection_state().await
    }
}

#[cfg(test)]
mod tests;
