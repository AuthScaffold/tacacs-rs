//! Shared state types for the mock transport: [`MockState`] and [`ReplyConfig`].
//!
//! These types contain the mock data. A `tokio::sync::Mutex` protects
//! [`MockState`]. An `Arc` shares it between the write processor and the
//! [`MockTransportCoordinator`](super::MockTransportCoordinator).

use std::collections::HashMap;
use std::time::Duration;

use tacacsrs_messages::packet::Packet;

/// Configuration for one predefined reply.
///
/// Stored in [`MockState::replies`] and consumed by the write processor when a
/// matching request arrives.
#[derive(Clone, Debug)]
pub(in crate::transport::mock) struct ReplyConfig {
    /// The raw serialized TACACS+ packet bytes to return.
    pub(in crate::transport::mock) bytes: Vec<u8>,
    /// Optional reply delay for timeout tests.
    pub(in crate::transport::mock) delay: Option<Duration>,
}

/// Shared mutable state between the write processor and the
/// [`MockTransportCoordinator`](super::MockTransportCoordinator).
///
/// A `tokio::sync::Mutex` protects this state. The write processor and
/// coordinator can access it concurrently without blocking the Tokio runtime.
#[derive(Debug, Default)]
pub(in crate::transport::mock) struct MockState {
    /// Predefined replies, keyed by `session_id → seq_no → ReplyConfig`.
    ///
    /// The write processor removes an entry when it matches a request. Each
    /// reply is delivered at most once.
    pub(in crate::transport::mock) replies: HashMap<u32, HashMap<u8, ReplyConfig>>,

    /// Captured request packets, keyed by `session_id → seq_no → Packet`.
    ///
    /// The write processor adds these packets. Tests read them through
    /// [`MockTransportCoordinator::get_requests_for_session`](super::MockTransportCoordinator::get_requests_for_session).
    ///
    /// The mock stores these packets as they appear on the wire. It does not
    /// deobfuscate them. If the connection uses an obfuscation key, the packet
    /// bodies remain obfuscated. Callers must deobfuscate them before they
    /// inspect cleartext content.
    pub(in crate::transport::mock) requests: HashMap<u32, HashMap<u8, Packet>>,
}
