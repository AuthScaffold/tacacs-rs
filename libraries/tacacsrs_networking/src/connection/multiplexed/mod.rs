//! Multiplexed TACACS+ packet connection runtime.
//!
//! This module drives a confirmed single-connection transport and manages the
//! lifecycle of multiple TACACS+ sessions over it.
//!
//! # Architecture
//!
//! The connection handler separates these functions:
//! - **Transport**: The underlying TCP or TLS connection. See
//!   [`transport`](crate::transport).
//! - **Session management**: This module creates and tracks sessions.
//! - **Packet I/O**: [`PacketReader`] and [`PacketWriter`] read and write packets.
//!
//! This module is crate-private. External callers must create
//! [`TacacsClient`](crate::TacacsClient) and run higher-level
//! flows over the returned session object.

use std::sync::{Arc, OnceLock};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use crate::connection::task::DriverTask;

use crate::codec::{PacketReadResult, PacketReader, PacketWriter};

mod write_loop;

use crate::single_connect::{LocalSingleConnectState, SingleConnectFlag, SingleConnectionState};
use crate::session::{
    ExpectedResponseHeader, PacketDispatchError, SessionManager, SharedFixedSession, SharedSession,
};

use self::write_loop::run_write_loop;

/// A multiplexed TACACS+ connection runtime.
///
/// `MultiplexedConnection` manages many TACACS+ sessions over one connection.
/// It handles:
///
/// - Concurrent packet reading and writing
/// - Session creation and management
/// - Single-connect mode negotiation
/// - Connection shutdown coordination
///
/// Wrap the connection in an `Arc` to share it across tasks.
pub(crate) struct MultiplexedConnection {
    session_manager: Arc<SessionManager>,
    runtime: Arc<ConnectionRuntime>,
    driver: OnceLock<DriverTask>,
}

struct ConnectionRuntime {
    session_manager: Arc<SessionManager>,
    packet_reader: PacketReader,
    packet_writer: PacketWriter,
}

struct SessionCleanup(Arc<SessionManager>);

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.0.disable_new_sessions();
        self.0.close_all_sessions();
    }
}

impl MultiplexedConnection {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(obfuscation_key: Option<&[u8]>) -> Self {
        Self::with_manager(Arc::new(SessionManager::new()), obfuscation_key, None)
    }

    /// Creates a connection whose single-connect support has already been confirmed.
    ///
    /// Use this when taking over a connection from a dedicated probe exchange that
    /// received `TAC_PLUS_SINGLE_CONNECT_FLAG` from the server.
    #[must_use]
    pub(crate) fn new_single_connect_confirmed(
        obfuscation_key: Option<&[u8]>,
        counters: Option<crate::ServerCounters>,
    ) -> Self {
        Self::with_manager(
            Arc::new(SessionManager::with_state(SingleConnectionState::Supported)),
            obfuscation_key,
            counters,
        )
    }

    fn with_manager(
        session_manager: Arc<SessionManager>,
        obfuscation_key: Option<&[u8]>,
        counters: Option<crate::ServerCounters>,
    ) -> Self {
        let key = obfuscation_key.map(<[u8]>::to_vec);
        Self {
            runtime: Arc::new(ConnectionRuntime {
                session_manager: Arc::clone(&session_manager),
                packet_reader: PacketReader::new(key.clone()).with_counters(counters.clone()),
                packet_writer: PacketWriter::new(key).with_counters(counters),
            }),
            session_manager,
            driver: OnceLock::new(),
        }
    }

    pub(crate) fn run_with_halves<R, W>(self: &Arc<Self>, reader: R, writer: W)
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let runtime = Arc::clone(&self.runtime);
        self.driver.get_or_init(|| {
            let cleanup = SessionCleanup(Arc::clone(&self.session_manager));
            DriverTask::spawn(async move {
                let _cleanup = cleanup;
                runtime
                    .handle_connection_with_halves(BufReader::new(reader), writer)
                    .await
            })
        });
    }

    pub(crate) async fn close_and_join(
        &self,
        deadline: crate::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.session_manager.disable_new_sessions();
        if let Some(driver) = self.driver.get() {
            driver.join_until(deadline).await?;
        }
        Ok(())
    }

    pub(crate) fn driver_finished(&self) -> bool {
        self.driver.get().is_none_or(DriverTask::is_finished)
    }

    #[cfg(test)]
    async fn handle_connection_with_halves<R, W>(&self, reader: R, writer: W) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        self.runtime
            .handle_connection_with_halves(reader, writer)
            .await
    }
}

impl ConnectionRuntime {
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
                        target: "tacacsrs_networking::connection::multiplexed::handle_connection",
                        "Write task failed: {error}"
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
                        target: "tacacsrs_networking::connection::multiplexed::handle_connection",
                        "Read task failed: {error}"
                    );

                    Err(error)
                }
            }
        };

        let result = tokio::try_join!(write_future, read_future);

        self.session_manager.disable_new_sessions();
        self.session_manager.close_all_sessions();

        result?;
        Ok(())
    }

    /// Internal read handler loop.
    ///
    /// Reads packets from the connection and sends them to the correct session.
    ///
    /// This loop also observes the first reply that established single-connect
    /// mode. RFC 8907 requires later packets to ignore this flag.
    ///
    /// ```text
    /// confirmed shared connection starts as Supported
    ///     |
    ///     v
    /// read server packet
    ///     |
    ///     +-- ignore single-connect flag and keep accepting shared sessions
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
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "The connection is retired and all sessions are complete."
                    );
                    return Ok(());
                }

                result = self.packet_reader.read_packet(reader) => result
            };

            let packet = match read_result {
                PacketReadResult::Success(packet) => packet,
                PacketReadResult::HeaderReadError(error) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Failed to read TACACS+ packet header: {error}"
                    );
                    return Err(error).context("failed to read TACACS+ packet header");
                }
                PacketReadResult::HeaderParseError(error) => {
                    log::error!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Failed to parse TACACS+ packet header: {error}"
                    );
                    return Err(error).context("failed to parse TACACS+ packet header");
                }
                PacketReadResult::BodyLengthExceeded {
                    session_id,
                    body_length,
                    max_length,
                } => {
                    log::error!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Rejected packet for session ID {session_id}: body length {body_length} exceeds maximum {max_length}. Closing the connection to prevent packet framing errors."
                    );
                    return Err(anyhow::Error::msg(format!(
                        "Packet body length {body_length} exceeds maximum {max_length}"
                    )));
                }
                PacketReadResult::BodyReadError { session_id, error } => {
                    log::error!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Failed to read packet body for session ID {session_id}: {error}"
                    );
                    return Err(error).context("failed to read TACACS+ packet body");
                }
                PacketReadResult::PacketCreateError { session_id, error } => {
                    log::error!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Failed to create packet for session ID {session_id}: {error}"
                    );
                    continue;
                }
            };

            let flag = SingleConnectFlag::from_packet(&packet);
            local_state = local_state.process_packet(flag, &self.session_manager);

            match self.session_manager.send_message_to_session(packet).await {
                Ok(()) => {}
                Err(
                    PacketDispatchError::UnknownSession(_) | PacketDispatchError::SessionClosed(_),
                ) => {
                    log::debug!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Ignoring response for a session that is no longer active"
                    );
                }
                Err(error @ PacketDispatchError::ProtocolViolation { .. }) => {
                    return Err(error.into());
                }
            }
        }
    }
}

impl MultiplexedConnection {
    pub(crate) fn can_create_sessions(self: &Arc<Self>) -> bool {
        self.session_manager.can_create_sessions()
    }

    pub(crate) fn disable_new_sessions(self: &Arc<Self>) {
        self.session_manager.disable_new_sessions();
    }

    pub(crate) fn create_session(self: &Arc<Self>) -> anyhow::Result<SharedSession> {
        let mut session = self.session_manager.create_session()?;
        session.connection_owner = Some(Arc::clone(self));
        Ok(session)
    }

    pub(crate) fn create_fixed_session(
        self: &Arc<Self>,
        expected: ExpectedResponseHeader,
    ) -> anyhow::Result<SharedFixedSession> {
        let mut session = self.session_manager.create_fixed_session(expected)?;
        session.connection_owner = Some(Arc::clone(self));
        Ok(session)
    }

    pub(crate) fn single_connection_state(self: &Arc<Self>) -> SingleConnectionState {
        self.session_manager.single_connection_state()
    }
}

#[cfg(test)]
mod tests;
