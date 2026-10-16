#![doc = include_str!("../README.md")]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-agent-client supports Linux GNU only");

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

/// Generated protobuf/gRPC types for the local IPC transport.
///
/// The checked-in `.proto` file
/// ([`proto/tacacsrs_agent.proto`](https://github.com/AuthScaffold/tacacs-rs/blob/main/libraries/tacacsrs_agent_client/proto/tacacsrs_agent.proto))
/// defines the wire IPC contract. The crate includes generated Rust bindings at
/// build time. It uses them to convert between domain types and the transport
/// schema.
///
/// > **Note:** This module suppresses all Clippy lints because
/// > `tonic-prost-build` generates the code.
pub mod ipc;

mod convert;

pub use client::ServiceClient;
pub use endpoint::IpcEndpoint;
pub use health::HealthClient;
