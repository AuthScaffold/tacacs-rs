//! Session scope: per-operation session handles over a packet connection.
//!
//! A session is one TACACS+ exchange identity (a session ID and its packet
//! routing) over a [`connection`](crate::connection) runtime. The internal
//! [`ClientSession`] facade hides whether an operation runs over a dedicated or a
//! shared transport:
//!
//! - [`DedicatedSession`] owns its own single-exchange connection.
//! - [`SharedSession`] and [`SharedFixedSession`] borrow a
//!   [`MultiplexedConnection`](crate::connection::MultiplexedConnection) route.
//!
//! [`SessionManager`] and [`SessionIdAllocator`] own packet dispatch and session
//! ID reservation. [`ClientConversation`] is the public, sequential packet
//! conversation built on a session.

mod channel;
mod conversation;
mod dedicated;
mod handle;
mod id;
mod manager;
mod shared;
mod shared_fixed;

pub use conversation::ClientConversation;
pub(crate) use handle::ClientSession;
pub(crate) use channel::DuplexChannel;
pub(crate) use dedicated::DedicatedSession;
pub(crate) use id::{ReservedSessionId, SessionIdAllocator, random_nonzero_session_id};
pub(crate) use manager::{ExpectedResponseHeader, PacketDispatchError, SessionManager};
pub(crate) use shared::SharedSession;
pub(crate) use shared_fixed::SharedFixedSession;
