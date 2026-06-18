//! TACACS+ client-side transport setup and session I/O.
//!
//! The public API intentionally stops at [`TacacsClient`] and
//! [`ClientSession`]. Callers create sessions here, then run protocol
//! flows from higher-level crates over the returned session I/O object. Raw
//! packet readers and writers are exposed only for adapter layers that must
//! bridge TACACS+ packets without interpreting operation bodies.

mod client;
mod codec;
mod establish;
mod helpers;
mod runtime;
mod session;
mod single_connect;
mod transport;

pub use client::TacacsClient;
pub use codec::{
    PacketReadResult, PacketReader, PacketReaderTrait, PacketWriteResult, PacketWriter,
    PacketWriterTrait,
};
pub use establish::{ConnectOptions, ConnectPreflight};
pub use session::ClientSession;
