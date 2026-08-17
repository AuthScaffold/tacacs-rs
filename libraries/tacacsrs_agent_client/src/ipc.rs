//! Generated protobuf/gRPC types for the local IPC transport.
//!
//! The checked-in `.proto` file defines the wire IPC contract:
//!
//! [`proto/tacacsrs_agent.proto`](https://github.com/AuthScaffold/tacacs-rs/blob/main/libraries/tacacsrs_agent_client/proto/tacacsrs_agent.proto)
//!
//! [`tonic::include_proto!`] includes the generated Rust bindings at build
//! time. The crate uses these bindings to convert between domain types and the
//! transport schema. No manually maintained serialization code is necessary.
//!
//! # Generated contents
//!
//! The protobuf schema produces the following Rust types:
//!
//! | Proto type | Rust type |
//! |------------|-----------|
//! | `AccountingRequest` | request message |
//! | `AccountingResponse` | response message |
//! | `AccountingReply` | oneof reply envelope |
//! | `AuthorizationRequest` | request message |
//! | `AuthorizationResponse` | response message |
//! | `AuthorizationReply` | oneof reply envelope |
//! | `ServiceError` | structured error |
//! | `AccountingStatus` | status enum |
//! | `AuthorizationStatus` | status enum |
//! | `TacacsAgent` | server/client trait + stubs |
//!
//! > **Note:** This module suppresses all Clippy lints because
//! > `tonic-prost-build` generates the code.

#![allow(clippy::all, clippy::pedantic)]

tonic::include_proto!("tacacsrs.agent.v1");
