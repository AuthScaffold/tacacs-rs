//! Long-lived agent runtime lifecycle.
//!
//! This module validates startup configuration and applies datastore reloads.
//! It also controls warm-up and graceful shutdown. The client API service
//! handles local client protocols. The upstream manager selects servers and
//! controls failover.

mod client_service;
mod config_filter;
mod config_supervisor;
mod health;
mod materialization_coordinator;
mod policy_supervisor;
mod proxy_loop_guard;
mod request_tracker;
mod server_catalog;
mod shutdown;

pub use client_service::TacacsClientService;
pub use config_filter::{FilteredTacacsPlus, NoopTacacsPlusFilter, TacacsPlusFilter};
pub use config_supervisor::ConfigSupervisor;
pub use policy_supervisor::PolicySupervisor;
pub use health::{
    DatastoreState, DegradationReason, ListenerState, RuntimeHealthPublisher,
    RuntimeHealthSnapshot, RuntimeLifecycle, RuntimeService, UpstreamAvailability,
};

#[cfg(test)]
pub(crate) use server_catalog::REQUIRED_SERVER_TYPES;
pub(crate) use server_catalog::enumerate_supported_servers;
pub(crate) use proxy_loop_guard::{ProxyLoopGuard, ProxyListenerBinding};
pub(crate) use request_tracker::{RequestGuard, RequestTracker};
pub(crate) use shutdown::{ListenerRegistration, ShutdownCoordinator, ShutdownReceiver};
