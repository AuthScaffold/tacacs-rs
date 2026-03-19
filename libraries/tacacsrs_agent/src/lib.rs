#![doc = include_str!("../README.md")]

/// Local listener, failover coordinator, and graceful-shutdown behavior.
///
/// This module contains the public [`TacacsClientService`] entry point and the
/// internal [`ServiceConfig`] consumed at startup. Underneath it delegates to
/// a shared state machine that routes each IPC request to an upstream
/// TACACS+ server and manages ordered failover.
pub mod service;

/// Persistent upstream TACACS+ connection management.
///
/// This module adapts the lower-level networking/session APIs into the
/// service's higher-level operation model. Each upstream connection can be
/// reused for many IPC requests, while the service keeps ownership of failover
/// decisions and connection lifecycle.
pub mod upstream;

pub use service::{ServiceConfig, TacacsClientService};
pub use upstream::UpstreamConnectionOptions;
