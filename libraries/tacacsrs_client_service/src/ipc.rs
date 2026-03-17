//! Generated protobuf/gRPC types for the local IPC transport.
//!
//! The `.proto` file is checked into the repository as the source of truth for
//! the on-the-wire IPC contract. The generated Rust bindings are included at
//! build time so the rest of the crate can convert between domain types and the
//! transport schema without hand-maintaining serialization code.

#![allow(clippy::all, clippy::pedantic)]

tonic::include_proto!("tacacsrs.client_service.v1");
