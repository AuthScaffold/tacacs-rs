//! Local client API listener and protobuf/gRPC adapter layer.
//!
//! The client API service controls how local clients connect to the agent. It
//! contains the Tonic services, Unix domain socket setup, loopback TCP setup,
//! and graceful listener drain. Its upstream bridge converts local requests to
//! TACACS+ messages. It sends these messages through the shared upstream
//! manager.

mod grpc;
mod health;
pub(crate) mod listener;
mod service;
mod upstream_bridge;

pub(crate) use service::ClientApiService;
pub(crate) use grpc::GrpcService;
