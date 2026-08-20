//! Single-connection state tracking for TACACS+ connections.
//!
//! This module tracks the single-connect flag locally across packets. It
//! notifies the session manager only when the state changes.

use std::sync::Arc;

use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;

use crate::session::SessionManager;

/// Represents whether the `TAC_PLUS_SINGLE_CONNECT_FLAG` is set in a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SingleConnectFlag {
    /// The `TAC_PLUS_SINGLE_CONNECT_FLAG` is set.
    Set,
    /// The `TAC_PLUS_SINGLE_CONNECT_FLAG` is not set.
    NotSet,
}

impl SingleConnectFlag {
    /// Returns the single-connect flag state from a packet.
    pub(crate) fn from_packet(packet: &impl PacketTrait) -> Self {
        if packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
        {
            Self::Set
        } else {
            Self::NotSet
        }
    }
}

/// Local state machine for single-connection mode.
///
/// This state mirrors the session manager state and reduces async calls. It:
/// - starts negotiation on the first packet,
/// - ignores the single-connect flag after the first packet, and
/// - enters a terminal state if the server does not support single-connection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LocalSingleConnectState {
    /// No packet has arrived. Notify the session manager when the first packet arrives.
    #[default]
    AwaitingFirstPacket,
    /// The server supports single-connection mode. Monitor the flag for removal.
    Supported,
    /// The server does not support single-connection mode. This state is terminal.
    NotSupported,
}

impl LocalSingleConnectState {
    /// Processes a packet and returns the new state.
    ///
    /// This function notifies the session manager when necessary.
    ///
    /// # State Transitions
    ///
    /// ```text
    /// [AwaitingFirstPacket]
    ///     |
    ///     | first packet
    ///     v
    /// flag set?
    ///     |
    ///     +-- yes --> [Supported]
    ///     |              |
    ///     |              +-- later flags are ignored
    ///     |
    ///     +-- no ---> [NotSupported] (terminal)
    /// ```
    pub(crate) async fn process_packet(
        self,
        flag: SingleConnectFlag,
        connection: &Arc<SessionManager>,
    ) -> Self {
        match (self, flag) {
            (Self::AwaitingFirstPacket, SingleConnectFlag::Set) => {
                connection.set_single_connection_state(true).await;
                Self::Supported
            }
            (Self::AwaitingFirstPacket, SingleConnectFlag::NotSet) => {
                connection.set_single_connection_state(false).await;
                Self::NotSupported
            }
            (Self::Supported, _) => Self::Supported,
            (Self::NotSupported, _) => {
                // This state is terminal.
                Self::NotSupported
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_awaiting_first_packet_with_flag_set() {
        let connection = Arc::new(SessionManager::new());
        let state = LocalSingleConnectState::AwaitingFirstPacket;

        let new_state = state
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        assert_eq!(new_state, LocalSingleConnectState::Supported);
    }

    #[tokio::test]
    async fn test_awaiting_first_packet_with_flag_not_set() {
        let connection = Arc::new(SessionManager::new());
        let state = LocalSingleConnectState::AwaitingFirstPacket;

        let new_state = state
            .process_packet(SingleConnectFlag::NotSet, &connection)
            .await;

        assert_eq!(new_state, LocalSingleConnectState::NotSupported);
    }

    #[tokio::test]
    async fn test_supported_remains_supported_when_flag_set() {
        let connection = Arc::new(SessionManager::new());
        // First, change to the Supported state.
        let state = LocalSingleConnectState::AwaitingFirstPacket
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        // Make sure that the state remains Supported.
        let new_state = state
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        assert_eq!(new_state, LocalSingleConnectState::Supported);
    }

    #[tokio::test]
    async fn test_supported_ignores_unset_flag_after_negotiation() {
        let connection = Arc::new(SessionManager::new());
        let state = LocalSingleConnectState::AwaitingFirstPacket
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        let new_state = state
            .process_packet(SingleConnectFlag::NotSet, &connection)
            .await;

        assert_eq!(new_state, LocalSingleConnectState::Supported);
        assert!(connection.can_create_sessions().await);
    }

    #[tokio::test]
    async fn test_not_supported_is_terminal_state() {
        let connection = Arc::new(SessionManager::new());
        // First, change to the NotSupported state.
        let state = LocalSingleConnectState::AwaitingFirstPacket
            .process_packet(SingleConnectFlag::NotSet, &connection)
            .await;

        // The state does not change if the server later sends the flag.
        let new_state = state
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        assert_eq!(new_state, LocalSingleConnectState::NotSupported);
    }
}
