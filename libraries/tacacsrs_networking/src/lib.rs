//! TACACS+ client-side transport setup and exchange execution.
//!
//! Fixed operations run through [`TacacsClient::execute`]. Transparent proxy
//! and interactive use cases open a [`ClientConversation`]. Raw packet codecs
//! are exposed only for adapter layers that bridge TACACS+ streams.

mod client;
mod codec;
mod establish;
mod exchange;
mod helpers;
mod runtime;
mod session;
mod single_connect;
mod transport;

pub use client::TacacsClient;
pub use codec::{PacketReadResult, PacketReader, PacketWriteResult, PacketWriter};
pub use establish::{ConnectOptions, ConnectPreflight};
pub use exchange::FixedExchange;
pub use session::ClientConversation;
