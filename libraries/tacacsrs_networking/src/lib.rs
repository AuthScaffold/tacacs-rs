//! TACACS+ client-side transport setup and exchange execution.
//!
//! Run fixed operations through [`TacacsClient::execute`]. Open a
//! [`ClientConversation`] for transparent proxy and interactive use cases. Raw
//! packet codecs are available only to adapter layers that bridge TACACS+
//! connections.
//! Use [`routed::RoutedClient`] to select operation-eligible endpoints and share
//! circuit and reconnect state without an agent or configuration source.
//!
//! Hosts can attach a [`ConnectionGuard`] through [`PreparedEndpoint::with_connection_guard`].
//! Establishment checks each resolved destination before TCP connect and checks the
//! connected socket before TLS or TACACS+ I/O. Endpoint clones share the guard.
//! The host owns listener state and interface discovery. Networking does not interpret YANG.
//!
//! Certificate TLS validates local and peer authentication dates during each
//! handshake. Established connections continue after those dates expire.
//! Independent OCSP and CRL freshness can still close a transport.
//!
//! Prepare security once, then finalize an endpoint without resolving DNS:
//!
//! ```
//! use tacacsrs_networking::{
//!     CertificateTrust, CertificateVerification, ConnectOptions, PreparedEndpoint, PreparedTransport,
//!     ServerAddress, TlsClientConfig,
//! };
//!
//! let tls = TlsClientConfig::prepare(
//!     "server.example", None, CertificateTrust::Platform, None, CertificateVerification::Required,
//! )?;
//! let endpoint = PreparedEndpoint::new(
//!     ServerAddress::new("server.example", 300)?, PreparedTransport::Tls(tls),
//!     true, None, ConnectOptions::default(),
//! );
//! assert_eq!(endpoint.address().port(), 300);
//! # anyhow::Ok(())
//! ```

mod client;
pub mod admission;
mod deadline;
mod codec;
mod endpoint;
mod preparation_payload;
mod establish;
mod exchange_error;
mod destination;
pub mod retry;
pub mod routed;
mod connection;
mod session;
mod single_connect;
mod transport;
mod statistics;

pub use client::TacacsClient;
pub use statistics::{
    ConnectionDetails, DiagnosticsSnapshot, DisconnectReason, OperationStatistics, ServerCounters,
    StatisticsSnapshot, TlsDetails,
};
pub use deadline::{DeadlineElapsed, RequestDeadline};
pub use codec::{PacketReadResult, PacketReader, PacketWriteResult, PacketWriter};
pub use endpoint::{ConnectionGuard, PreparedEndpoint};
pub use preparation_payload::{PreparationPayload, PreparationPayloadLedger};
pub use destination::ServerAddress;
pub use transport::tls::{
    CertificateIdentity, CertificateTrust, CertificateVerification, CertificateRevocationPolicy,
    PrivateKeyEncoding, RevocationEvidenceValidity, TlsClientConfig,
};
pub use transport::tls_psk::{PskClientConfig, PskHash, PskDheGroup};
pub use establish::{ConnectOptions, ConnectPreflight, PreparedTransport};
pub use exchange_error::{FixedExchangeError, TransmissionState};
pub use session::ClientConversation;
