//! Central TACACS+ client service building blocks.
//!
//! This crate separates the reusable service implementation from the runnable
//! executable in `executables/tacacs_client_service`. Its main pieces are:
//!
//! - [`client`] for short-lived local IPC request/response clients
//! - [`protocol`] for the transport-independent RPC contract and JSON schema
//! - [`service`] for the long-lived local listener and failover coordinator
//! - [`upstream`] for persistent TACACS+ server connectivity
//! - [`codec`] for framed JSON transport over Unix sockets or loopback TCP
//!
//! The current scope focuses on accounting while keeping the protocol and
//! service structure extensible for future authentication and authorization
//! operations.

pub mod client;
pub mod codec;
pub mod protocol;
pub mod service;
pub mod upstream;

pub use client::ServiceClient;
pub use protocol::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus, ServiceError,
    ServiceRequest, ServiceResponse,
};
pub use service::{IpcEndpoint, ServiceConfig, TacacsClientService};
pub use upstream::UpstreamConnectionOptions;
