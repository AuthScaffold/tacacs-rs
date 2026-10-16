//! Connection scope: packet-connection runtimes beneath a client session.
//!
//! A connection owns packet I/O over one transport. Two runtimes implement the
//! two TACACS+ connection shapes:
//!
//! - [`DedicatedConnection`]: one request/response exchange on a single
//!   transport, then close. The client owns dedicated connections directly.
//! - [`MultiplexedConnection`]: many concurrent TACACS+ sessions over one
//!   confirmed single-connection transport, driven by an owned read/write task.
//!
//! A confirmed single-connection probe promotes a [`BoxedDedicatedConnection`]
//! into a [`MultiplexedConnection`]; the
//! [`single_connect`](crate::single_connect) cache then owns the promoted
//! connection. The [`session`](crate::session) module layers session handles over
//! these runtimes, so callers never hold a runtime directly.

mod dedicated;
pub(crate) mod task;
mod multiplexed;

use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) use dedicated::DedicatedConnection;
pub(crate) use multiplexed::MultiplexedConnection;

/// A dedicated connection with type-erased, boxed transport halves.
///
/// This is the form a dedicated client session owns and the form a confirmed
/// single-connection promotion upgrades into a shared connection.
pub(crate) type BoxedDedicatedConnection =
    DedicatedConnection<Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>>;
