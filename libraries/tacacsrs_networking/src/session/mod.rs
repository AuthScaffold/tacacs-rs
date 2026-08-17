//! Session implementations and session ID ownership.
//!
//! The internal [`ClientSession`] facade delegates to a concrete session
//! implementation. The multiplexed connection runtime creates
//! [`SharedSession`] values. The client facade owns dedicated sessions.

mod channel;
mod client;
mod conversation;
mod dedicated;
mod id;
mod manager;
mod shared;
mod shared_fixed;

pub use conversation::ClientConversation;
pub(crate) use client::ClientSession;
pub(crate) use channel::DuplexChannel;
pub(crate) use dedicated::{DedicatedSession, SingleConnectPromotion};
pub(crate) use id::{ReservedSessionId, SessionIdAllocator, random_nonzero_session_id};
pub(crate) use manager::{ExpectedResponseHeader, PacketDispatchError, SessionManager};
pub(crate) use shared::SharedSession;
pub(crate) use shared_fixed::SharedFixedSession;
