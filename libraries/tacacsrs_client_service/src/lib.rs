#![doc = include_str!("../README.md")]

pub mod client;
mod ipc;
pub mod protocol;
pub mod service;
pub mod upstream;

pub use client::ServiceClient;
pub use protocol::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus, ServiceError,
};
pub use service::{IpcEndpoint, ServiceConfig, TacacsClientService};
pub use upstream::UpstreamConnectionOptions;
