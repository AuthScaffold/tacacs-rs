#![doc = include_str!("../README.md")]

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
