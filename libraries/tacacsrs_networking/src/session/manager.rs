use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tacacsrs_messages::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::single_connect::SingleConnectionState;

use super::{DuplexChannel, ReservedSessionId, SessionIdAllocator, SharedFixedSession, SharedSession};

/// Outbound packet queue depth for one multiplexed connection.
///
/// This matches the local agent's default concurrent request limit, so a full
/// queue reflects real admission pressure instead of an unrelated bound.
const CONNECTION_QUEUE_CAPACITY: usize = 64;

/// Inbound packet queue depth for one session.
const SESSION_QUEUE_CAPACITY: usize = 32;

#[derive(Debug)]
struct ActiveSessionEntry {
    route: ActiveSessionRoute,
    _reservation: ReservedSessionId,
}

#[derive(Debug)]
enum ActiveSessionRoute {
    Conversation(mpsc::Sender<Packet>),
    Fixed {
        sender: Option<oneshot::Sender<anyhow::Result<Packet>>>,
        expected: ExpectedResponseHeader,
    },
}

enum DispatchTarget {
    Conversation(mpsc::Sender<Packet>),
    Fixed {
        sender: oneshot::Sender<anyhow::Result<Packet>>,
        expected: ExpectedResponseHeader,
    },
}

/// Header metadata a fixed exchange requires from its single reply.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExpectedResponseHeader {
    major_version: TacacsMajorVersion,
    minor_version: TacacsMinorVersion,
    tacacs_type: TacacsType,
    seq_no: u8,
}

impl ExpectedResponseHeader {
    pub(crate) const fn fixed(tacacs_type: TacacsType, minor_version: TacacsMinorVersion) -> Self {
        Self {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version,
            tacacs_type,
            seq_no: 2,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_request(packet: &Packet) -> Self {
        let header = packet.header();
        Self {
            major_version: header.major_version,
            minor_version: header.minor_version,
            tacacs_type: header.tacacs_type,
            seq_no: header.seq_no.wrapping_add(1),
        }
    }

    fn validate(self, packet: &Packet) -> anyhow::Result<()> {
        let header = packet.header();
        if header.major_version != self.major_version
            || header.minor_version != self.minor_version
            || header.tacacs_type != self.tacacs_type
            || header.seq_no != self.seq_no
        {
            anyhow::bail!(
                "unexpected TACACS+ response header for session {:#x}: seq_no={}, type={}, version={:?}.{:?}; expected seq_no={}, type={}, version={:?}.{:?}",
                header.session_id,
                header.seq_no,
                header.tacacs_type,
                header.major_version,
                header.minor_version,
                self.seq_no,
                self.tacacs_type,
                self.major_version,
                self.minor_version,
            );
        }
        Ok(())
    }
}

/// Classifies packet dispatch failures for connection-lifetime decisions.
#[derive(Debug)]
pub(crate) enum PacketDispatchError {
    UnknownSession(u32),
    SessionClosed(u32),
    ProtocolViolation { session_id: u32, message: String },
}

impl fmt::Display for PacketDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSession(session_id) => {
                write!(formatter, "no route for TACACS+ session {session_id:#x}")
            }
            Self::SessionClosed(session_id) => {
                write!(formatter, "route for TACACS+ session {session_id:#x} is closed")
            }
            Self::ProtocolViolation {
                session_id,
                message,
            } => write!(
                formatter,
                "protocol violation for TACACS+ session {session_id:#x}: {message}"
            ),
        }
    }
}

impl Error for PacketDispatchError {}

#[derive(Debug)]
pub(crate) struct SessionManager {
    duplex_channels: Mutex<HashMap<u32, ActiveSessionEntry>>,
    sender: tokio::sync::mpsc::Sender<Packet>,
    receiver: Mutex<Option<tokio::sync::mpsc::Receiver<Packet>>>,
    session_id_allocator: Arc<SessionIdAllocator>,

    can_accept_new_sessions: AtomicBool,

    /// Tracks whether the server supports single-connection mode.
    /// This state is `Initial` until the first session starts.
    single_connection_state: Mutex<SingleConnectionState>,

    /// Notifies waiters when they must close the connection.
    /// This occurs after the last session completes if the server does not
    /// support single-connection mode.
    close_notify: Notify,
}

impl SessionManager {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_state(SingleConnectionState::Initial)
    }

    pub(crate) fn with_state(initial_state: SingleConnectionState) -> Self {
        let (sender, receiver) = mpsc::channel::<Packet>(CONNECTION_QUEUE_CAPACITY);

        Self {
            duplex_channels: HashMap::new().into(),
            sender,
            receiver: Some(receiver).into(),
            session_id_allocator: SessionIdAllocator::new(),
            can_accept_new_sessions: AtomicBool::new(true),
            single_connection_state: initial_state.into(),
            close_notify: Notify::new(),
        }
    }

    fn routes(&self) -> std::sync::MutexGuard<'_, HashMap<u32, ActiveSessionEntry>> {
        self.duplex_channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn connection_state(&self) -> std::sync::MutexGuard<'_, SingleConnectionState> {
        self.single_connection_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn disable_new_sessions(&self) {
        self.can_accept_new_sessions.store(false, Ordering::Release);
    }

    fn create_channel(&self) -> (DuplexChannel, u32) {
        let reserved_session_id = self.session_id_allocator.reserve_generated();
        let session_id = reserved_session_id.get();

        // Create the channels after validation.
        let (session_sender, session_receiver) = mpsc::channel::<Packet>(SESSION_QUEUE_CAPACITY);
        let duplex_channel = DuplexChannel::new(session_receiver, self.sender.clone());

        // Insert the new session.
        self.routes().insert(
            session_id,
            ActiveSessionEntry {
                route: ActiveSessionRoute::Conversation(session_sender),
                _reservation: reserved_session_id,
            },
        );

        (duplex_channel, session_id)
    }

    /// Replaces a conversation inbox with a one-shot fixed response route.
    #[cfg(test)]
    pub(crate) fn prepare_fixed_response(
        &self,
        session_id: u32,
        expected: ExpectedResponseHeader,
    ) -> anyhow::Result<oneshot::Receiver<anyhow::Result<Packet>>> {
        let (sender, receiver) = oneshot::channel();
        let mut routes = self.routes();
        let entry = routes
            .get_mut(&session_id)
            .ok_or_else(|| anyhow::anyhow!("no route for TACACS+ session {session_id:#x}"))?;

        match entry.route {
            ActiveSessionRoute::Conversation(_) => {
                entry.route = ActiveSessionRoute::Fixed {
                    sender: Some(sender),
                    expected,
                };
                Ok(receiver)
            }
            ActiveSessionRoute::Fixed { .. } => {
                anyhow::bail!("TACACS+ session {session_id:#x} already awaits a fixed response")
            }
        }
    }

    pub(crate) fn can_create_sessions(&self) -> bool {
        if !self.can_accept_new_sessions.load(Ordering::Acquire) {
            return false;
        }

        // Check the single-connection state.
        let state = *self.connection_state();
        match state {
            SingleConnectionState::NotSupported | SingleConnectionState::Negotiating => false,
            SingleConnectionState::Supported | SingleConnectionState::Initial => true,
        }
    }

    /// Returns the current single-connection state.
    pub(crate) fn single_connection_state(&self) -> SingleConnectionState {
        *self.connection_state()
    }

    /// Sets the single-connection state from the server response.
    ///
    /// Call this function when a packet arrives from the server.
    ///
    /// ## State transition rules
    ///
    /// - `Negotiating` → `Supported` or `NotSupported` (based on flag)
    /// - `Supported` → (terminal for this connection)
    /// - `NotSupported` → (terminal, no transitions allowed)
    /// - `Initial` → (ignored, must go through `Negotiating` first)
    ///
    /// ```text
    /// [Initial]
    ///     |
    ///     | try_begin_session
    ///     v
    /// [Negotiating]
    ///     |
    ///     +-- server flag set ----> [Supported]
    ///     |
    ///     +-- server flag absent -> [NotSupported]
    ///
    /// [Supported] and [NotSupported] are terminal for this connection.
    /// ```
    pub(crate) fn set_single_connection_state(&self, server_supports_single_connection: bool) {
        let mut state = self.connection_state();

        if *state == SingleConnectionState::Negotiating {
            let new_state = if server_supports_single_connection {
                SingleConnectionState::Supported
            } else {
                SingleConnectionState::NotSupported
            };

            *state = new_state;
            drop(state);

            log::info!(
                target: "tacacsrs_networking::session::manager::set_single_connection_state",
                "Set single-connection state to {new_state:?}"
            );
        } else {
            let current = *state;
            drop(state);

            log::debug!(
                target: "tacacsrs_networking::session::manager::set_single_connection_state",
                "Ignored single-connection update {server_supports_single_connection} because the state is {current:?}",
            );
        }
    }

    /// Checks session creation and starts negotiation in one atomic operation.
    ///
    /// This prevents concurrent tasks from passing the session check before the
    /// state changes to `Negotiating`.
    ///
    /// Returns `Ok(())` if a session can be created.
    fn try_begin_session(&self) -> anyhow::Result<()> {
        // First, check whether the connection accepts new sessions.
        if !self.can_accept_new_sessions.load(Ordering::Acquire) {
            return Err(anyhow::Error::msg("Connection is not accepting new sessions"));
        }

        // Check and change the state while holding one lock.
        let mut state = self.connection_state();
        match *state {
            SingleConnectionState::NotSupported | SingleConnectionState::Negotiating => {
                Err(anyhow::Error::msg("Connection is not accepting new sessions"))
            }
            SingleConnectionState::Initial => {
                // Change to Negotiating while holding the same lock.
                log::debug!(
                    target: "tacacsrs_networking::session::manager::try_begin_session",
                    "Changed single-connection state from Initial to Negotiating"
                );
                *state = SingleConnectionState::Negotiating;
                Ok(())
            }
            SingleConnectionState::Supported => Ok(()),
        }
    }

    /// Returns `true` if the server does not support single-connection mode.
    ///
    /// Close the connection after the current session completes when this
    /// function returns `true`.
    #[cfg(test)]
    pub(crate) fn should_close_after_session(&self) -> bool {
        *self.connection_state() == SingleConnectionState::NotSupported
    }

    /// # Errors
    /// Returns an error if the connection is not accepting new sessions.
    pub(crate) fn create_session(self: &Arc<Self>) -> anyhow::Result<SharedSession> {
        // Check session creation and start negotiation in one atomic operation.
        self.try_begin_session()?;

        let (duplex_channel, session_id) = self.create_channel();

        log::trace!(
            target: "tacacsrs_networking::session::manager::create_session",
            "Created session with ID {session_id}"
        );

        Ok(SharedSession::new_with_manager(session_id, duplex_channel, Some(Arc::clone(self))))
    }

    /// Creates a fixed one-shot route without allocating a per-session mpsc channel.
    pub(crate) fn create_fixed_session(
        self: &Arc<Self>,
        expected: ExpectedResponseHeader,
    ) -> anyhow::Result<SharedFixedSession> {
        self.try_begin_session()?;
        let reservation = self.session_id_allocator.reserve_generated();
        let session_id = reservation.get();
        let (response_sender, response_receiver) = oneshot::channel();
        self.routes().insert(
            session_id,
            ActiveSessionEntry {
                route: ActiveSessionRoute::Fixed {
                    sender: Some(response_sender),
                    expected,
                },
                _reservation: reservation,
            },
        );
        Ok(SharedFixedSession::new(
            session_id,
            self.sender.clone(),
            response_receiver,
            Arc::clone(self),
        ))
    }

    pub(crate) fn remove_session(&self, session_id: u32) {
        let mut duplex_channels = self.routes();
        if duplex_channels.remove(&session_id).is_some() {
            log::trace!(
                target: "tacacsrs_networking::session::manager::remove_session",
                "Removed session {session_id} from the session registry"
            );

            // Check whether to signal connection closure. Hold the registry lock
            // during this check. This prevents creation of a session between the
            // empty-registry check and the close signal.
            if duplex_channels.is_empty() {
                let should_close = *self.connection_state() == SingleConnectionState::NotSupported;
                drop(duplex_channels);

                if should_close {
                    log::info!(
                        target: "tacacsrs_networking::session::manager::remove_session",
                        "The last session completed, and single-connection mode is not supported. Signaling connection closure"
                    );
                    self.close_notify.notify_waiters();
                }
            }
        }
    }

    /// Waits until the connection must close.
    ///
    /// This returns after the last session completes if the server does not
    /// support single-connection mode.
    pub(crate) async fn wait_for_close(&self) {
        self.close_notify.notified().await;
    }

    pub(crate) fn take_receiver(&self) -> Option<mpsc::Receiver<Packet>> {
        self.receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Closes all sessions by clearing the session registry.
    ///
    /// Waiting session receivers get `None` and can stop.
    pub(crate) fn close_all_sessions(&self) {
        let mut duplex_channels = self.routes();
        let session_count = duplex_channels.len();
        duplex_channels.clear();
        drop(duplex_channels);

        log::info!(
            target: "tacacsrs_networking::session::manager::close_all_sessions",
            "Closed all {session_count} sessions in the session registry"
        );
    }

    /// # Errors
    /// Returns an error if the session is not found in the registry.
    pub(crate) async fn send_message_to_session(
        &self,
        packet: Packet,
    ) -> Result<(), PacketDispatchError> {
        let session_id = packet.header().session_id;
        let target = {
            let mut routes = self.routes();
            match routes.get_mut(&session_id) {
                Some(ActiveSessionEntry {
                    route: ActiveSessionRoute::Conversation(sender),
                    ..
                }) => DispatchTarget::Conversation(sender.clone()),
                Some(ActiveSessionEntry {
                    route: ActiveSessionRoute::Fixed { sender, expected },
                    ..
                }) => DispatchTarget::Fixed {
                    sender: sender
                        .take()
                        .ok_or(PacketDispatchError::SessionClosed(session_id))?,
                    expected: *expected,
                },
                None => return Err(PacketDispatchError::UnknownSession(session_id)),
            }
        };

        match target {
            DispatchTarget::Conversation(sender) => {
                log::trace!(
                    target: "tacacsrs_networking::session::manager::send_message_to_session",
                    "Found channel for session ID {session_id}. Sending packet to the session"
                );

                match sender.send(packet).await {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.remove_session(session_id);

                        log::warn!(
                            target: "tacacsrs_networking::session::manager::send_message_to_session",
                            "Failed to send packet to channel for session ID {session_id}: {e}"
                        );

                        Err(PacketDispatchError::SessionClosed(session_id))
                    }
                }
            }
            DispatchTarget::Fixed { sender, expected } => {
                if let Err(error) = expected.validate(&packet) {
                    let message = error.to_string();
                    let _ = sender.send(Err(error));
                    return Err(PacketDispatchError::ProtocolViolation {
                        session_id,
                        message,
                    });
                }

                sender
                    .send(Ok(packet))
                    .map_err(|_| PacketDispatchError::SessionClosed(session_id))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacacsrs_messages::enumerations::{
        TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;

    #[tokio::test]
    async fn test_create_channel() {
        let session_manager = SessionManager::new();

        let (_, session_id) = session_manager.create_channel();

        assert_ne!(session_id, 0);
    }

    #[tokio::test]
    async fn test_create_channel_generates_unique_session_ids() {
        let session_manager = SessionManager::new();

        let (_, session_id) = session_manager.create_channel();
        let (_, session_id2) = session_manager.create_channel();

        assert_ne!(session_id, session_id2);
    }

    #[tokio::test]
    async fn test_create_session() {
        let session_manager = Arc::new(SessionManager::new());

        let session = session_manager.create_session().unwrap();

        assert_ne!(session.session_id(), 0);
    }

    #[tokio::test]
    async fn test_create_session_when_connection_is_not_accepting_new_sessions() {
        let session_manager = Arc::new(SessionManager::new());

        session_manager.disable_new_sessions();

        let result = session_manager.create_session();

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_session_when_connection_is_not_accepting_new_sessions_and_has_existing_sessions(
    ) {
        let session_manager = Arc::new(SessionManager::new());

        // Session creation succeeds while the connection accepts new sessions.
        _ = session_manager.create_session().unwrap();

        session_manager.disable_new_sessions();

        // Session creation fails after the connection stops accepting new sessions.
        let result = session_manager.create_session();

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_session_complete_removes_from_registry() {
        let session_manager = Arc::new(SessionManager::new());

        let session = session_manager.create_session().unwrap();
        let session_id = session.session_id();

        // Make sure that the registry contains the session.
        let contains_session = {
            let channels = session_manager.routes();
            channels.contains_key(&session_id)
        };
        assert!(contains_session);

        // Complete the session to remove it from the registry.
        session.complete();

        // Make sure that the registry no longer contains the session.
        let contains_session = {
            let channels = session_manager.routes();
            channels.contains_key(&session_id)
        };
        assert!(!contains_session);
    }

    #[tokio::test]
    async fn test_dropping_session_removes_it_from_registry() {
        let session_manager = Arc::new(SessionManager::new());

        let session = session_manager.create_session().unwrap();
        let session_id = session.session_id();
        session_manager.set_single_connection_state(true);

        drop(session);

        assert!(!session_manager.routes().contains_key(&session_id));
    }

    #[tokio::test]
    async fn test_send_message_to_closed_session_reaps_registry_entry() {
        let session_manager = Arc::new(SessionManager::new());

        let session = session_manager.create_session().unwrap();
        let session_id = session.session_id();
        session_manager.set_single_connection_state(true);
        session.close_receiver().await;

        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: 1,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id,
                length: 0,
            },
            Vec::new(),
        )
        .unwrap();
        let result = session_manager.send_message_to_session(packet).await;

        assert!(result.is_err());

        let contains_session = {
            let channels = session_manager.routes();
            channels.contains_key(&session_id)
        };
        assert!(!contains_session);

        drop(session);
    }

    #[tokio::test]
    async fn test_single_connection_state_starts_initial() {
        let session_manager = SessionManager::new();
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Initial);
    }

    #[tokio::test]
    async fn test_single_connection_state_transitions_to_negotiating() {
        let session_manager = Arc::new(SessionManager::new());

        // The state is Initial before session creation.
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Initial);

        // Create the first session and change the state to Negotiating.
        let _session1 = session_manager.create_session().unwrap();
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Negotiating);
    }

    #[tokio::test]
    async fn test_single_connection_state_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create a session to change the state to Negotiating.
        let _session1 = session_manager.create_session().unwrap();

        // Simulate a server response that confirms support.
        session_manager.set_single_connection_state(true);
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Supported);
    }

    #[tokio::test]
    async fn test_single_connection_state_not_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create a session to change the state to Negotiating.
        let _session1 = session_manager.create_session().unwrap();

        // Simulate a server response that denies support.
        session_manager.set_single_connection_state(false);
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::NotSupported);
    }

    #[tokio::test]
    async fn test_single_connection_state_cannot_transition_from_not_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create a session and set the state to NotSupported.
        let _session1 = session_manager.create_session().unwrap();
        session_manager.set_single_connection_state(false);
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::NotSupported);

        // Try to change the state to Supported. NotSupported is terminal.
        session_manager.set_single_connection_state(true);
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::NotSupported);
    }

    #[tokio::test]
    async fn test_supported_state_ignores_later_unset_flag() {
        let session_manager = Arc::new(SessionManager::new());

        let _session1 = session_manager.create_session().unwrap();
        session_manager.set_single_connection_state(true);
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Supported);

        session_manager.set_single_connection_state(false);

        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Supported);
        assert!(session_manager.can_create_sessions());
        assert!(!session_manager.should_close_after_session());
    }

    /// Makes sure that the state remains Supported while the server sends the flag.
    ///
    /// This prevents unnecessary logs and state updates.
    #[tokio::test]
    async fn test_supported_state_remains_supported_when_flag_still_set() {
        let session_manager = Arc::new(SessionManager::new());

        // Create a session and set the state to Supported.
        let _session1 = session_manager.create_session().unwrap();
        session_manager.set_single_connection_state(true);
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Supported);

        // Process multiple packets that contain the flag.
        session_manager.set_single_connection_state(true);
        session_manager.set_single_connection_state(true);
        session_manager.set_single_connection_state(true);

        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Supported);
    }

    /// Tests the complete graceful-shutdown flow.
    ///
    /// The server initially supports single-connection mode and then signals
    /// shutdown. The test makes sure that:
    /// 1. The connection blocks new sessions after the shutdown signal.
    /// 2. Active sessions can complete.
    /// 3. The connection signals closure after the last session completes.
    #[tokio::test]
    async fn test_cannot_create_second_session_when_negotiating() {
        let session_manager = Arc::new(SessionManager::new());

        // The first session succeeds and changes the state to Negotiating.
        let _session1 = session_manager.create_session().unwrap();
        assert_eq!(session_manager.single_connection_state(), SingleConnectionState::Negotiating);

        // The second session fails because negotiation is still active.
        let result = session_manager.create_session();
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("not accepting new sessions"));
    }

    #[tokio::test]
    async fn test_can_create_multiple_sessions_when_state_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create the first session and simulate a response with the single-connect flag.
        let _session1 = session_manager.create_session().unwrap();
        session_manager.set_single_connection_state(true);

        // Multiple sessions succeed when single-connection mode is supported.
        let _session2 = session_manager.create_session().unwrap();
        let _session3 = session_manager.create_session().unwrap();
    }

    #[tokio::test]
    async fn test_cannot_create_session_when_state_not_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create the first session before support is known.
        let _session1 = session_manager.create_session().unwrap();

        // Set the state to NotSupported.
        session_manager.set_single_connection_state(false);

        // New sessions fail when single-connection mode is not supported.
        let result = session_manager.create_session();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_should_close_after_session() {
        let session_manager = Arc::new(SessionManager::new());

        // The connection stays open in the Initial state.
        assert!(!session_manager.should_close_after_session());

        // Create a session and set the state to Supported.
        let _session1 = session_manager.create_session().unwrap();
        session_manager.set_single_connection_state(true);

        // The connection stays open in the Supported state.
        assert!(!session_manager.should_close_after_session());
    }

    #[tokio::test]
    async fn test_should_close_after_session_when_not_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create a session and set the state to NotSupported.
        let _session1 = session_manager.create_session().unwrap();
        session_manager.set_single_connection_state(false);

        // The connection closes in the NotSupported state.
        assert!(session_manager.should_close_after_session());
    }

    /// Makes sure that concurrent session creation permits only one initial session.
    ///
    /// This test covers a race that previously let multiple tasks create sessions
    /// before the state changed from Initial to Negotiating.
    #[tokio::test]
    async fn test_concurrent_session_creation_from_initial_state() {
        // Run multiple iterations to increase the chance of detecting a race.
        for _ in 0..100 {
            let session_manager = Arc::new(SessionManager::new());

            // Start multiple concurrent session-creation tasks.
            let mut handles = Vec::new();
            for _ in 0..10 {
                let sm = Arc::clone(&session_manager);
                handles.push(tokio::spawn(async move { sm.create_session() }));
            }

            // Wait for all tasks.
            let results: Vec<_> = futures::future::join_all(handles)
                .await
                .into_iter()
                .map(|r| r.unwrap())
                .collect();

            // Exactly one session succeeds and changes the state to Negotiating.
            // All other sessions fail.
            let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
            let failures: Vec<_> = results.iter().filter(|r| r.is_err()).collect();

            assert_eq!(
                successes.len(),
                1,
                "expected exactly one successful session creation, but got {}. \
                 Multiple tasks created sessions before the state changed to Negotiating",
                successes.len()
            );
            assert_eq!(
                failures.len(),
                9,
                "expected nine failed session creations, but got {}",
                failures.len()
            );

            // Make sure that the first session changed the state to Negotiating.
            assert_eq!(
                session_manager.single_connection_state(),
                SingleConnectionState::Negotiating,
                "state must be Negotiating after the first session is created"
            );
        }
    }

    /// Makes sure that concurrent session creation works in the Supported state.
    ///
    /// All concurrent session-creation tasks must succeed when the server
    /// supports single-connection mode.
    #[tokio::test]
    async fn test_concurrent_session_creation_when_supported() {
        let session_manager = Arc::new(SessionManager::new());

        // Create the first session and enable single-connection mode.
        let _session1 = session_manager.create_session().unwrap();
        session_manager.set_single_connection_state(true);

        // Start multiple concurrent session-creation tasks.
        let mut handles = Vec::new();
        for _ in 0..10 {
            let sm = Arc::clone(&session_manager);
            handles.push(tokio::spawn(async move { sm.create_session() }));
        }

        // Wait for all tasks.
        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Make sure that all sessions succeed.
        let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
        assert_eq!(
            successes.len(),
            10,
            "all session creations must succeed in the Supported state, but got {} successes",
            successes.len()
        );
    }

    /// Makes sure that session creation and removal do not race with close notification.
    ///
    /// This test covers a race that previously let a new session start after
    /// removal of the last session but before the close check.
    #[tokio::test]
    async fn test_remove_session_and_create_session_no_race_on_close() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::time::{timeout, Duration};

        // Run multiple iterations to increase the chance of detecting a race.
        for iteration in 0..50 {
            let session_manager = Arc::new(SessionManager::new());
            let close_notifications = Arc::new(AtomicUsize::new(0));

            // Create the first session. Closure of the last session causes a
            // close notification after the state changes to NotSupported.
            let session1 = session_manager.create_session().unwrap();
            session_manager.set_single_connection_state(true);

            // Start a close-notification waiter.
            let sm_for_waiter = Arc::clone(&session_manager);
            let close_count = Arc::clone(&close_notifications);
            let waiter_handle = tokio::spawn(async move {
                // Use a timeout to prevent the test from waiting indefinitely.
                if timeout(Duration::from_millis(100), sm_for_waiter.wait_for_close())
                    .await
                    .is_ok()
                {
                    close_count.fetch_add(1, Ordering::SeqCst);
                }
            });

            // Change the state to NotSupported.
            {
                let mut state = session_manager.connection_state();
                *state = SingleConnectionState::NotSupported;
            }

            // Start a task that completes the session.
            let sm_for_complete = Arc::clone(&session_manager);
            let session_id = session1.session_id();
            let complete_handle = tokio::spawn(async move {
                drop(session1); // Drop schedules removal from the session registry.
                sm_for_complete.remove_session(session_id);
            });

            // Wait for completion.
            complete_handle.await.unwrap();

            // Let the waiter process the notification.
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Cancel the waiter if it still waits.
            waiter_handle.abort();
            let _ = waiter_handle.await;

            // Read the close-notification count.
            let notifications = close_notifications.load(Ordering::SeqCst);

            // Read the current session count.
            let session_count = session_manager.routes().len();

            // If no sessions remain, make sure that one close notification occurred.
            if session_count == 0 {
                assert_eq!(
                    notifications, 1,
                    "iteration {iteration}: expected one close notification after the last session \
                     completed in the NotSupported state, but got {notifications}"
                );
            }
        }
    }

    /// Makes sure that close notification occurs only after the last session completes.
    ///
    /// The notification must not occur while another session remains active.
    #[tokio::test]
    async fn test_close_not_signaled_while_sessions_exist() {
        let session_manager = Arc::new(SessionManager::new());

        // Create the first session and set the state to Supported.
        let session1 = session_manager.create_session().unwrap();
        session_manager.set_single_connection_state(true);

        // Create a second session.
        let _session2 = session_manager.create_session().unwrap();

        // Change the state to NotSupported.
        {
            let mut state = session_manager.connection_state();
            *state = SingleConnectionState::NotSupported;
        }

        // Start a waiter that must not receive a notification.
        let sm_for_waiter = Arc::clone(&session_manager);
        let waiter_handle = tokio::spawn(async move {
            tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                sm_for_waiter.wait_for_close(),
            )
            .await
        });

        // Complete session1. Session2 remains active.
        session1.complete();

        // Wait for the timeout.
        let result = waiter_handle.await.unwrap();

        // Make sure that the wait times out while session2 is active.
        assert!(result.is_err(), "the connection must not close while a session is active");

        // Make sure that the registry still contains session2.
        let session_count = session_manager.routes().len();
        assert_eq!(session_count, 1, "session2 must remain in the registry");
    }
}
