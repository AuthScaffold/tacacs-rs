//! Shared state types for the mock transport: [`MockState`] and [`ReplyConfig`].
//!
//! These types are the data core of the mock infrastructure. [`MockState`] is
//! protected by a `tokio::sync::Mutex` and shared (via `Arc`) between the
//! background write processor task and the [`MockTransportCoordinator`](super::MockTransportCoordinator).

use std::collections::HashMap;
use std::time::Duration;

use tacacsrs_messages::packet::Packet;

/// Configuration for a single pre-configured reply.
///
/// Stored in [`MockState::replies`] and consumed by the write processor when a
/// matching request arrives.
#[derive(Clone, Debug)]
pub struct ReplyConfig {
    /// The raw serialised TACACS+ packet bytes to send back.
    pub(crate) bytes: Vec<u8>,
    /// Optional delay before delivering the reply, useful for testing timeouts.
    pub(crate) delay: Option<Duration>,
}

/// Shared mutable state between the write processor and the
/// [`MockTransportCoordinator`](super::MockTransportCoordinator).
///
/// Protected by a `tokio::sync::Mutex` so both the async write processor task
/// and the coordinator (which may be called concurrently from test code) can
/// access it without blocking the tokio runtime.
#[derive(Debug, Default)]
pub struct MockState {
    /// Pre-configured replies, keyed by `session_id → seq_no → ReplyConfig`.
    ///
    /// Entries are **removed** (consumed) when the write processor matches them
    /// to an incoming request. This means each reply is delivered at most once.
    pub(crate) replies: HashMap<u32, HashMap<u8, ReplyConfig>>,

    /// Captured request packets, keyed by `session_id → seq_no → Packet`.
    ///
    /// Populated by the write processor. Tests read these via
    /// [`MockTransportCoordinator::get_requests_for_session`](super::MockTransportCoordinator::get_requests_for_session).
    ///
    /// **Important:** These packets are stored as-is from the wire — the mock
    /// transport does **not** deobfuscate them. If the connection under test
    /// uses an obfuscation key, the packet bodies here will still be
    /// obfuscated. Callers must deobfuscate manually if they need to inspect
    /// cleartext content.
    pub(crate) requests: HashMap<u32, HashMap<u8, Packet>>,
}
