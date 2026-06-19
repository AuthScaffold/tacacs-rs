//! Local client API listener and protobuf/gRPC adapter layer.
//!
//! The client API service owns how local clients connect to the agent: Tonic
//! service implementations, Unix socket setup, loopback TCP setup, and graceful
//! listener drain. Its upstream bridge translates local operation requests into
//! TACACS+ protocol messages before sending them through the shared upstream
//! manager.

mod grpc;
pub(crate) mod listener;
mod service;
mod upstream_bridge;

pub(crate) use service::ClientApiService;
pub(crate) use grpc::GrpcService;
