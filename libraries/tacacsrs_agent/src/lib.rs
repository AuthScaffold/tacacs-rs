#![doc = include_str!("../README.md")]

/// Public configuration for the agent runtime.
pub mod config;

/// Local IPC adapters and listener infrastructure.
mod ipc;

/// Typed accounting and authorization execution over routed upstreams.
mod operations;

/// Long-lived service lifecycle and hot-reload orchestration.
pub mod runtime;

/// Upstream server routing, failover, connection cache, and drain tracking.
mod routing;

/// Persistent upstream TACACS+ connection management.
///
/// This module adapts lower-level networking/session APIs into the agent's
/// operation model. Each upstream connection can be reused for many IPC
/// requests, while the routing layer keeps ownership of failover decisions and
/// connection lifecycle.
pub mod upstream;

#[cfg(test)]
mod test_support;

pub use config::ServiceConfig;
pub use runtime::TacacsClientService;
