//! Multiplexed TACACS+ packet connection runtime.
//!
//! This module drives a confirmed single-connection transport and manages the
//! lifecycle of multiple TACACS+ sessions over it.
//!
//! An idle peer can close a connection between packets. The runtime retires that connection without a shutdown error. EOF during an active session or a partial packet remains an error.
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

use std::sync::{Arc, OnceLock, Weak};

use anyhow::Context;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tacacsrs_secrets::SecretBytes;
use crate::connection::failure::ConnectionFailure;
use crate::connection::task::DriverTask;

use crate::codec::{PacketReadResult, PacketReader, PacketWriter};
use crate::exchange_error::protocol_failure;

mod write_loop;

use crate::single_connect::{SingleConnectFlag, SingleConnectionState};
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
    cache_eviction: Option<(
        Weak<crate::single_connect::SharedConnectionCache>,
        Weak<crate::single_connect::NegotiationState>,
    )>,
}

struct ConnectionRuntime {
    session_manager: Arc<SessionManager>,
    packet_reader: PacketReader,
    packet_writer: PacketWriter,
    negotiate_single_connect: bool,
}

struct SessionCleanup(Arc<SessionManager>);

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.0.disable_new_sessions();
        drop(self.0.take_publication());
        self.0.close_all_sessions();
    }
}

impl MultiplexedConnection {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(obfuscation_key: Option<&[u8]>) -> Self {
        Self::with_manager(
            Arc::new(SessionManager::new()),
            obfuscation_key.map(|key| SecretBytes::new(key.to_vec())),
            None,
            false,
            None,
        )
    }

    /// Creates a connection that negotiates single-connection support on its first reply.
    #[must_use]
    pub(crate) fn new_negotiating(
        obfuscation_key: Option<SecretBytes>,
        counters: Option<crate::ServerCounters>,
        publication: crate::single_connect::FirstReplyPublication,
        shared_connection: Weak<crate::single_connect::SharedConnectionCache>,
        negotiation_state: Weak<crate::single_connect::NegotiationState>,
    ) -> Self {
        Self::with_manager(
            Arc::new(SessionManager::with_publication(publication)),
            obfuscation_key,
            counters,
            true,
            Some((shared_connection, negotiation_state)),
        )
    }

    /// Creates a connection whose single-connect support has already been confirmed.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_single_connect_confirmed(
        obfuscation_key: Option<SecretBytes>,
        counters: Option<crate::ServerCounters>,
    ) -> Self {
        Self::with_manager(
            Arc::new(SessionManager::with_state(SingleConnectionState::Supported)),
            obfuscation_key,
            counters,
            false,
            None,
        )
    }

    fn with_manager(
        session_manager: Arc<SessionManager>,
        obfuscation_key: Option<SecretBytes>,
        counters: Option<crate::ServerCounters>,
        negotiate_single_connect: bool,
        cache_eviction: Option<(
            Weak<crate::single_connect::SharedConnectionCache>,
            Weak<crate::single_connect::NegotiationState>,
        )>,
    ) -> Self {
        Self {
            runtime: Arc::new(ConnectionRuntime {
                session_manager: Arc::clone(&session_manager),
                packet_reader: PacketReader::new(obfuscation_key.clone())
                    .with_counters(counters.clone()),
                packet_writer: PacketWriter::new(obfuscation_key).with_counters(counters),
                negotiate_single_connect,
            }),
            session_manager,
            driver: OnceLock::new(),
            cache_eviction,
        }
    }

    pub(crate) fn run_with_halves<R, W>(self: &Arc<Self>, reader: R, writer: W)
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let runtime = Arc::clone(&self.runtime);
        let owner = Arc::downgrade(self);
        self.driver.get_or_init(|| {
            let cleanup = SessionCleanup(Arc::clone(&self.session_manager));
            DriverTask::spawn(async move {
                let _cleanup = cleanup;
                runtime
                    .handle_connection_with_halves(reader, writer, Some(owner))
                    .await
                    .map_err(|error| error.context(ConnectionFailure))
            })
        });
    }

    async fn evict_from_cache(self: &Arc<Self>) {
        if let Some((cache, state)) = &self.cache_eviction {
            if let (Some(cache), Some(state)) = (cache.upgrade(), state.upgrade()) {
                cache
                    .evict_if_same(self, || state.update(SingleConnectionState::Initial))
                    .await;
            }
        }
    }

    pub(crate) async fn abort_malformed(self: &Arc<Self>) {
        self.session_manager.disable_new_sessions();
        drop(self.session_manager.take_publication());
        if let Some(counters) = self.runtime.packet_writer.counters() {
            counters.disconnect_reason(crate::DisconnectReason::MalformedPacket);
        }
        self.evict_from_cache().await;
        if let Some(driver) = self.driver.get() {
            let _ = driver
                .join_until(
                    crate::RequestDeadline::after(std::time::Duration::ZERO)
                        .expect("zero duration fits instant"),
                )
                .await;
        }
    }

    pub(crate) async fn wait_driver_finished(&self) {
        if let Some(driver) = self.driver.get() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), driver.wait_finished())
                .await;
        }
    }

    pub(crate) fn record_negotiation_timeout(&self) {
        if self.session_manager.single_connection_state() == SingleConnectionState::Negotiating {
            if let Some(counters) = self.runtime.packet_writer.counters() {
                counters.disconnect_reason(crate::DisconnectReason::NoResponse);
            }
        }
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
            .handle_connection_with_halves(reader, writer, None)
            .await
    }
}

impl ConnectionRuntime {
    async fn handle_connection_with_halves<R, W>(
        &self,
        reader: R,
        mut writer: W,
        owner: Option<std::sync::Weak<MultiplexedConnection>>,
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut reader = BufReader::new(reader);
        self.handle_connection_halves(&mut reader, &mut writer, owner)
            .await
    }

    async fn handle_connection_halves<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        owner: Option<std::sync::Weak<MultiplexedConnection>>,
    ) -> anyhow::Result<()>
    where
        R: AsyncBufRead + Unpin + Send,
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
                self.negotiate_single_connect,
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
            match self.read_handler(reader, owner).await {
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
        self.session_manager
            .close_all_sessions_with_error(result.as_ref().err());

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
    async fn read_handler<R: AsyncBufRead + Unpin + Send>(
        &self,
        reader: &mut R,
        owner: Option<std::sync::Weak<MultiplexedConnection>>,
    ) -> anyhow::Result<()> {
        loop {
            let read_result = tokio::select! {
                () = self.session_manager.wait_for_close() => {
                    log::info!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "The connection is retired and all sessions are complete."
                    );
                    return Ok(());
                }

                result = async {
                    match reader.fill_buf().await {
                        Ok([]) if self.session_manager.retire_if_idle() => None,
                        Ok(_) => Some(self.packet_reader.read_packet(reader).await),
                        Err(error) => {
                            self.packet_reader.record_io_error(&error);
                            Some(PacketReadResult::HeaderReadError(error))
                        }
                    }
                } => result
            };

            let Some(read_result) = read_result else {
                log::info!("The upstream peer closed its idle TACACS+ connection");
                return Ok(());
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
                    if let Some(conn) = owner.as_ref().and_then(std::sync::Weak::upgrade) {
                        conn.evict_from_cache().await;
                    }
                    return Err(protocol_failure(
                        error.context("failed to parse TACACS+ packet header"),
                    ));
                }
                PacketReadResult::BodyLengthExceeded {
                    session_id,
                    body_length,
                    max_length,
                } => {
                    let correlation = tacacsrs_protocol::header::wire_correlation(session_id);
                    log::error!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Rejected packet for correlation {correlation}: body length {body_length} exceeds maximum {max_length}. Closing the connection to prevent packet framing errors."
                    );
                    if let Some(conn) = owner.as_ref().and_then(std::sync::Weak::upgrade) {
                        conn.evict_from_cache().await;
                    }
                    let error = protocol_failure(anyhow::Error::msg(format!(
                        "Packet body length {body_length} exceeds maximum {max_length}"
                    )));
                    return Err(self
                        .session_manager
                        .reject_fixed_response(session_id, error)
                        .into());
                }
                PacketReadResult::BodyReadError { session_id, error } => {
                    let correlation = tacacsrs_protocol::header::wire_correlation(session_id);
                    log::error!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Failed to read packet body for correlation {correlation}: {error}"
                    );
                    return Err(error).context("failed to read TACACS+ packet body");
                }
                PacketReadResult::PacketCreateError { session_id, error } => {
                    let correlation = tacacsrs_protocol::header::wire_correlation(session_id);
                    log::error!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Failed to create packet for correlation {correlation}: {error}"
                    );
                    continue;
                }
            };

            let flag = SingleConnectFlag::from_packet(&packet);

            match self.session_manager.prepare_dispatch(packet) {
                Ok(dispatch) => {
                    self.session_manager
                        .set_single_connection_state(flag.is_set());
                    if let Some(publication) = self.session_manager.take_publication() {
                        if let Some(conn) = owner.as_ref().and_then(std::sync::Weak::upgrade) {
                            publication
                                .settle(&conn, flag, self.packet_writer.counters().as_ref())
                                .await;
                        }
                    }
                    if let Err(
                        PacketDispatchError::UnknownSession(_)
                        | PacketDispatchError::SessionClosed(_),
                    ) = dispatch.deliver(&self.session_manager).await
                    {
                        log::debug!(
                            target: "tacacsrs_networking::connection::multiplexed::read_handler",
                            "Ignoring response for a session that is no longer active"
                        );
                    }
                }
                Err(
                    PacketDispatchError::UnknownSession(_) | PacketDispatchError::SessionClosed(_),
                ) => {
                    log::debug!(
                        target: "tacacsrs_networking::connection::multiplexed::read_handler",
                        "Ignoring response for a session that is no longer active"
                    );
                }
                Err(error @ PacketDispatchError::ProtocolViolation { .. }) => {
                    if let Some(counters) = self.packet_writer.counters() {
                        counters.disconnect_reason(crate::DisconnectReason::MalformedPacket);
                    }
                    if let Some(conn) = owner.as_ref().and_then(std::sync::Weak::upgrade) {
                        conn.evict_from_cache().await;
                    }
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
