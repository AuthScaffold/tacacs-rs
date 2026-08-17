//! Packet-connection runtimes.
//!
//! Runtime modules control packet connections. The dedicated runtime
//! performs one request/response exchange on a single transport, while the
//! multiplexed runtime runs many TACACS+ sessions over a confirmed
//! single-connection transport.

mod dedicated;
mod multiplexed;

pub(crate) use dedicated::DedicatedConnection;
pub(crate) use multiplexed::MultiplexedConnection;
