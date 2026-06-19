#![doc = include_str!("../README.md")]

/// Public configuration for the agent runtime.
pub mod config;

/// Long-lived service lifecycle and hot-reload orchestration.
pub mod runtime;

/// Internal services with explicit runtime ownership boundaries.
mod services;

/// Persistent upstream TACACS+ connection management.
///
/// This module adapts lower-level networking/session APIs into the agent's
/// operation model. Each upstream connection can be reused for many IPC
/// requests, while the upstream manager keeps ownership of failover decisions
/// and connection lifecycle.
pub mod upstream;

#[cfg(test)]
mod test_support;

pub use config::{EnabledServices, ServiceConfig};
pub use runtime::TacacsClientService;
