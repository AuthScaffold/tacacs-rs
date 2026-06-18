//! Local IPC listener and protobuf/gRPC adapter layer.
//!
//! The IPC layer owns how local clients connect to the agent: Tonic service
//! implementations, Unix socket setup, loopback TCP setup, and graceful listener
//! drain. It delegates every decoded request into [`crate::routing`].

mod grpc;
pub(crate) mod listener;
pub(crate) mod proxy;

pub(crate) use grpc::GrpcService;
