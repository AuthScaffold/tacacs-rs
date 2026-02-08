//! Single connection state tracking for TACACS+ connections.
//!
//! This module provides a local state machine for efficiently tracking the single connection
//! mode flag across packets. Instead of checking with the session manager on every packet,
//! we track state locally and only notify the session manager on state transitions.

use std::sync::Arc;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;
use crate::session_manager::SessionManager;

/// Represents whether the TAC_PLUS_SINGLE_CONNECT_FLAG is set in a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleConnectFlag {
    /// The TAC_PLUS_SINGLE_CONNECT_FLAG is set
    Set,
    /// The TAC_PLUS_SINGLE_CONNECT_FLAG is not set
    NotSet,
}

impl SingleConnectFlag {
    /// Extract the single connect flag state from a packet.
    pub fn from_packet(packet: &impl PacketTrait) -> Self {
        if packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
        {
            SingleConnectFlag::Set
        } else {
            SingleConnectFlag::NotSet
        }
    }
}

/// Local state machine for tracking single connection mode.
///
/// This mirrors the session manager state but is tracked locally to minimize async calls.
/// The state machine handles:
/// - Initial negotiation on first packet
/// - Detecting graceful shutdown when server removes the flag
/// - Terminal state when single connection is not supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalSingleConnectState {
    /// Haven't received any packets yet - need to notify on first packet
    #[default]
    AwaitingFirstPacket,
    /// Server supports single connection - watch for flag removal (graceful shutdown)
    Supported,
    /// Server doesn't support single connection - terminal state, no more checks needed
    NotSupported,
}


impl LocalSingleConnectState {
    /// Process a packet and return the new state, notifying the session manager if needed.
    ///
    /// # State Transitions
    ///
    /// ```text
    /// ┌──────────────────────────┐
    /// │   AwaitingFirstPacket    │
    /// └────────────┬─────────────┘
    ///              │ First packet received
    ///     ┌────────┴────────┐
    ///     │ flag set?       │
    ///     ▼                 ▼
    /// ┌─────────┐      ┌──────────────┐
    /// │Supported│      │ NotSupported │ (terminal)
    /// └────┬────┘      └──────────────┘
    ///      │ flag removed (graceful shutdown)
    ///      ▼
    /// ┌──────────────┐
    /// │ NotSupported │ (terminal)
    /// └──────────────┘
    /// ```
    pub async fn process_packet(
        self,
        flag: SingleConnectFlag,
        connection: &Arc<SessionManager>,
    ) -> Self {
        match (self, flag) {
            (LocalSingleConnectState::AwaitingFirstPacket, SingleConnectFlag::Set) => {
                connection.set_single_connection_state(true).await;
                LocalSingleConnectState::Supported
            }
            (LocalSingleConnectState::AwaitingFirstPacket, SingleConnectFlag::NotSet) => {
                connection.set_single_connection_state(false).await;
                LocalSingleConnectState::NotSupported
            }
            (LocalSingleConnectState::Supported, SingleConnectFlag::Set) => {
                LocalSingleConnectState::Supported
            }
            (LocalSingleConnectState::Supported, SingleConnectFlag::NotSet) => {
                // Server removed flag - graceful shutdown signal
                connection.set_single_connection_state(false).await;
                LocalSingleConnectState::NotSupported
            }
            (LocalSingleConnectState::NotSupported, _) => {
                // Terminal state - no further transitions
                LocalSingleConnectState::NotSupported
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
        // First get to Supported state
        let state = LocalSingleConnectState::AwaitingFirstPacket
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        // Now check that it remains Supported
        let new_state = state
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        assert_eq!(new_state, LocalSingleConnectState::Supported);
    }

    #[tokio::test]
    async fn test_supported_transitions_to_not_supported_on_graceful_shutdown() {
        let connection = Arc::new(SessionManager::new());
        // First get to Supported state
        let state = LocalSingleConnectState::AwaitingFirstPacket
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        // Server removes flag (graceful shutdown)
        let new_state = state
            .process_packet(SingleConnectFlag::NotSet, &connection)
            .await;

        assert_eq!(new_state, LocalSingleConnectState::NotSupported);
    }

    #[tokio::test]
    async fn test_not_supported_is_terminal_state() {
        let connection = Arc::new(SessionManager::new());
        // First get to NotSupported state
        let state = LocalSingleConnectState::AwaitingFirstPacket
            .process_packet(SingleConnectFlag::NotSet, &connection)
            .await;

        // Even if server now sends flag, state doesn't change
        let new_state = state
            .process_packet(SingleConnectFlag::Set, &connection)
            .await;

        assert_eq!(new_state, LocalSingleConnectState::NotSupported);
    }
}
