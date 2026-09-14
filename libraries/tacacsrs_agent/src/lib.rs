#![doc = include_str!("../README.md")]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-agent supports Linux GNU only");

/// Public configuration for the agent runtime.
pub mod config;

/// Long-lived service lifecycle and configuration reloads.
pub mod runtime;

/// Internal services with explicit runtime owners.
mod services;

/// Persistent upstream TACACS+ connection management.
///
/// This module adapts lower-level connection and session APIs to the agent
/// operation model. The upstream manager controls failover and the connection
/// lifecycle. It can reuse each server connection for many IPC requests.
pub mod upstream;

#[cfg(test)]
mod test_support;

pub use config::{
    EnabledServices, FailoverStrategy, OperationPolicies, PolicyService,
    ProxyDownstreamObfuscation, RequestLimits, RuntimePolicy, ServiceConfig,
};
pub use upstream::OperationKind;
pub use runtime::{
    DatastoreState, DegradationReason, ListenerState, LocalCapabilityExclusion,
    RequiredLocalCapability, RuntimeHealthPublisher, RuntimeHealthSnapshot, RuntimeLifecycle,
    RuntimeService, TacacsClientService, UpstreamAvailability,
};
