//! IPC server adapter over an operation [`Handler`].
//!
//! This module owns the local gRPC server adaptation for the central TACACS+
//! client service: the generated service implementation, the bounded incoming
//! transport, the standard health mapping, and the Unix domain socket listener.
//!
//! The interface is expressed in protocol-domain types through [`Handler`] and
//! in transport-neutral [`ListenerOptions`] and [`HealthStatus`] signals. The
//! module does not depend on the agent runtime, generated YANG configuration,
//! or a networking connector. A host supplies the handler and the neutral
//! options and health projection.

mod grpc;
mod handler;
mod health;
mod limited_incoming;
mod listener;
mod request_tracker;

pub use handler::Handler;
pub use health::HealthStatus;
pub use listener::{ListenerOptions, serve_unix};
