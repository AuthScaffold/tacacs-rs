//! Persistent upstream TACACS+ connection management.
//!
//! This module adapts lower-level connection and session APIs to the service
//! operation model. The service controls failover and the connection lifecycle.
//! It can reuse each server connection for many IPC requests.
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
//! | `client-identity` with `tls13-epsk` | TLS-PSK (feature-gated) |
//!
//! # Connection reuse
//!
//! Each server connection wraps one persistent TCP/TLS connection
//! to one TACACS+ server. The TACACS+ protocol supports multiplexed sessions
//! on one connection when both peers negotiate single-connection mode. If the
//! server does not support reuse, the connection stops accepting new sessions.
//! The service reconnects for the next IPC request.

mod admission;
mod attempt;
mod connection;
mod executor;
mod failover;
mod operation;
pub(crate) mod manager;
mod network;
mod proxy_transport;
mod router;

pub(crate) use connection::{UpstreamConnection, UpstreamConnector};
pub(crate) use attempt::{AttemptFailureKind, UpstreamRequestError};
pub(crate) use admission::{AdmissionError, AdmissionPermit};
pub(crate) use executor::{Attempt, FailoverAttempt, FailoverOutcome, run_with_failover};
pub(crate) use failover::{AttemptDisposition, FailoverPlan};
pub(crate) use network::NetworkUpstreamConnector;
pub(crate) use proxy_transport::ProxyTransportSettings;
pub(crate) use router::OperationRouter;
pub use operation::OperationKind;
