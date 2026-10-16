#![doc = include_str!("../README.md")]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-ipc supports Linux GNU only");

/// Local gRPC client helpers for communication with the central TACACS+ service.
///
/// The [`ServiceClient`] type is the main entry point. Callers construct it
/// with [`ServiceClient::connect`] and an [`IpcEndpoint`]. Callers then send
/// unary accounting or authorization RPCs over the persistent gRPC channel.
/// Each call converts between domain types and protobuf types.
pub mod client;

mod endpoint;

/// Stable names used by standard gRPC health checks.
pub mod health;

/// Generated protobuf and gRPC bindings for the local IPC transport.
///
/// The checked-in `.proto` file is the single source of truth for the wire
/// contract. See the module docs for the generated type listing.
pub mod proto;

mod convert;

pub mod server;

pub use client::ServiceClient;
pub use endpoint::IpcEndpoint;
pub use health::HealthClient;
