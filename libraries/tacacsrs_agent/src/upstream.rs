//! Persistent upstream TACACS+ connection management.
//!
//! This module adapts the lower-level networking/session APIs into the
//! service's higher-level operation model. Each upstream connection can be
//! reused for many IPC requests, while the service keeps ownership of failover
//! decisions and connection lifecycle.
//!
//! # Transport selection
//!
//! Each [`tacacsrs_config::TacacsPlusServer`] carries the YANG model fields that determine which transport is
//! used for the upstream TACACS+ connection:
//!
//! | Security | Transport |
//! |----------|-----------|
//! | `shared-secret` only | Plain TCP |
//! | no TLS fields and no `shared-secret` | Plain TCP without TACACS+ obfuscation |
//! | `client-identity` / `server-authentication` (certificate) | mTLS (X.509) |
//! | `client-identity` with `tls13-epsk` | TLS-PSK (feature-gated) |
//!
//! # Connection reuse
//!
//! Each upstream connection wraps a single persistent TCP/TLS connection
//! to one TACACS+ server. The TACACS+ protocol supports multiplexed sessions
//! over one connection when both sides negotiate single-connection mode. If
//! the server does not support reuse, the connection reports itself as
//! unusable for new sessions and the service reconnects for the next IPC
//! request.

mod mapping;
mod network;
mod traits;

pub(crate) use network::NetworkUpstreamConnector;
pub(crate) use traits::{UpstreamConnection, UpstreamConnector};
