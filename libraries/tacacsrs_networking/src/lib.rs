//! TACACS+ client-side transport setup and exchange execution.
//!
//! Run fixed operations through [`TacacsClient::execute`]. Open a
//! [`ClientConversation`] for transparent proxy and interactive use cases. Raw
//! packet codecs are available only to adapter layers that bridge TACACS+
//! connections.

mod client;
mod codec;
mod establish;
mod exchange;
mod exchange_error;
mod helpers;
mod runtime;
mod session;
mod single_connect;
mod transport;

pub use client::TacacsClient;
pub use codec::{PacketReadResult, PacketReader, PacketWriteResult, PacketWriter};
pub use establish::{ConnectOptions, ConnectPreflight};
pub use exchange::FixedExchange;
pub use exchange_error::{FixedExchangeError, TransmissionState};
pub use session::ClientConversation;
