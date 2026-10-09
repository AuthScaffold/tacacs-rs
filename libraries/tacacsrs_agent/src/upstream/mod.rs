//! Service adapters for prepared upstream catalogs and TACACS+ exchanges.
//!
//! Networking owns route selection, circuits, reconnect serialization, and the
//! conservative retry executor. The agent projects canonical configuration and
//! retains admission, source metadata, health, and local service policy.
//!
//! # Transport selection
//!
//! Each [`tacacsrs_config::TacacsPlusServer`] contains the YANG model fields
//! that select the transport for the TACACS+ server connection:
//!
//! | Security | Transport |
//! |----------|-----------|
//! | `shared-secret` only | Plain TCP |
//! | No TLS fields and no `shared-secret` | Plain TCP without TACACS+ obfuscation |
//! | `client-identity` / `server-authentication` (certificate) | mTLS (X.509) |
//! | `client-identity` with `tls13-epsk` | TLS-PSK |
//!
//! # Connection reuse
//!
//! Each operation has an adaptive client. It caches a shared TCP/TLS connection
//! when both peers negotiate single-connection mode. Otherwise, each session
//! opens a dedicated connection. Prepared endpoint identities control cache
//! reuse across published catalogs.

mod admission;
mod attempt;
mod connection;
pub(crate) mod manager;
mod network;
mod proxy_transport;
mod router;

pub(crate) use connection::UpstreamConnection;
#[cfg(test)]
pub(crate) use connection::UpstreamConnector;
pub(crate) use attempt::{AttemptFailureKind, UpstreamRequestError};
pub(crate) use admission::{AdmissionError, AdmissionPermit};
pub(crate) use network::NetworkUpstreamConnector;
pub(crate) use proxy_transport::ProxyTransportSettings;
pub(crate) use router::{OperationRouter, RequestRouting};
pub use tacacsrs_networking::routed::OperationKind;
