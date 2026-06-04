//! Session implementations and session ID ownership.
//!
//! The public [`ClientSession`] facade delegates to one
//! of the concrete session implementations here. The multiplexed connection
//! runtime creates [`SharedSession`] values, while dedicated sessions live with
//! the client facade until they can be split out behind the same boundary.

mod channel;
mod client;
mod dedicated;
mod id;
mod manager;
mod shared;

pub use client::ClientSession;
pub(crate) use channel::DuplexChannel;
pub(crate) use dedicated::{DedicatedSession, SingleConnectPromotion};
pub(crate) use id::{ReservedSessionId, SessionIdAllocator, random_nonzero_session_id};
pub(crate) use manager::SessionManager;
pub(crate) use shared::SharedSession;
