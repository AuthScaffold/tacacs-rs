//! TACACS+ client-side transport setup and exchange execution.
//!
//! Run fixed operations through [`TacacsClient::execute`]. Open a
//! [`ClientConversation`] for transparent proxy and interactive use cases. Raw
//! packet codecs are available only to adapter layers that bridge TACACS+
//! connections.
//!
//! Hosts can attach a [`ConnectionGuard`] through [`PreparedEndpoint::with_connection_guard`].
//! Establishment checks each resolved destination before TCP connect and checks the
//! connected socket before TLS or TACACS+ I/O. Endpoint clones share the guard.
//! The host owns listener state and interface discovery. Networking does not interpret YANG.

mod client;
mod codec;
mod endpoint;
mod establish;
mod exchange_error;
mod helpers;
mod runtime;
mod session;
mod single_connect;
mod transport;

pub use client::TacacsClient;
pub use codec::{PacketReadResult, PacketReader, PacketWriteResult, PacketWriter};
pub use endpoint::{ConnectionGuard, PreparedEndpoint};
pub use transport::tls::{CertificateIdentity, CertificateTrust, PrivateKeyEncoding};
pub use transport::tls_psk::{PskHash, PskDheGroup};
pub use establish::{ConnectOptions, ConnectPreflight};
pub use exchange_error::{FixedExchangeError, TransmissionState};
pub use session::ClientConversation;
