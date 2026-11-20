//! Generated protobuf/gRPC types for the local IPC transport.
//!
//! The checked-in `.proto` files define the wire IPC contract. Both files use
//! the `tacacsrs.agent.v1` package:
//!
//! - [`proto/tacacsrs_agent.proto`](https://github.com/AuthScaffold/tacacs-rs/blob/main/libraries/tacacsrs_ipc/proto/tacacsrs_agent.proto)
//!   defines the operations and the statistics.
//! - [`proto/tacacsrs_agent_health.proto`](https://github.com/AuthScaffold/tacacs-rs/blob/main/libraries/tacacsrs_ipc/proto/tacacsrs_agent_health.proto)
//!   defines the detailed runtime health.
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
//! | `Diagnostics` | server/client trait + stubs |
//! | `HealthDetailsReply` | detailed runtime health |
//! | `ComponentHealth` | result of one component health check |
//! | `AgentHealth` | server/client trait + stubs |
//!
//! > **Note:** This module suppresses all Clippy lints because
//! > `tonic-prost-build` generates the code.

#![allow(clippy::all, clippy::pedantic)]

tonic::include_proto!("tacacsrs.agent.v1");
