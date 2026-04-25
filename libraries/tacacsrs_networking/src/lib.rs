//! TACACS+ networking primitives, session handling, and transport abstractions.
//!
//! Transport support is organized in [`transport`], with shared traits in
//! [`transport::abstractions`] and protocol-specific implementations in
//! `transport::tcp`, `transport::tls`, and the feature-gated
//! `transport::tls_psk` module.
//!
//! TLS and TLS-PSK connections are constructed exclusively from the YANG
//! configuration model via [`config_connect::establish_stream`]; the
//! lower-level builder/handshake helpers in the TLS modules are internal to
//! this crate.

pub mod sender;
pub mod session;
mod session_id;
pub mod sessions;
pub mod duplex_channel;
pub mod session_manager;
pub mod helpers;
pub mod traits;
pub mod packet_reader;
pub mod packet_writer;
pub mod single_connect_tracker;
pub mod transport;
pub mod connection;
pub mod config_connect;
pub mod dedicated_connection;

pub use session_manager::SingleConnectionState;
pub use packet_reader::{PacketReader, PacketReaderTrait, PacketReadResult};
pub use packet_writer::{PacketWriter, PacketWriterTrait, PacketWriteResult};
pub use single_connect_tracker::{LocalSingleConnectState, SingleConnectFlag};
pub use connection::TacacsConnection;
pub use dedicated_connection::{DedicatedConnection, ExchangeResult};
pub use transport::Transport;
pub use transport::BoxedTransport;
pub use transport::mock::MockTransport;
