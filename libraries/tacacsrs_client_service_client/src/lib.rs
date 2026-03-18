//! Client-facing IPC types and helpers for talking to the central TACACS+
//! client service.

pub mod client;
mod endpoint;
pub mod ipc;
pub mod protocol;

pub use client::ServiceClient;
pub use endpoint::IpcEndpoint;
pub use protocol::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus, ServiceError,
};
