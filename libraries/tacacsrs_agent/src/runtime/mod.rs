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
mod listener_service;
mod materialization_coordinator;
pub(crate) mod candidate_preparation;
mod policy_supervisor;
mod proxy_loop_guard;
mod request_tracker;
mod revision;
mod server_catalog;
mod shutdown;

pub use client_service::{DiagnosticsHandle, ListenerSettings, TacacsClientService};
pub use config_filter::{FilteredTacacsPlus, NoopTacacsPlusFilter, TacacsPlusFilter};
pub use config_supervisor::ConfigSupervisor;
pub use listener_service::RuntimeListenerService;
pub use policy_supervisor::PolicySupervisor;
pub use revision::{
    CredentialRevision, MaterializationRevision, PolicyRevision, PolicyUpdate, SourceRevision,
};
pub(crate) use revision::{ExpiredMaterial, MaterialExpiry, MaterializationCommit};
mod credential_lifetime;
pub(crate) use credential_lifetime::CredentialLifetime;
pub use health::{
    DatastoreState, DegradationReason, ListenerState, RuntimeHealthPublisher, RuntimeGeneration,
    RuntimeHealthSnapshot, RuntimeLifecycle, RuntimeService, UpstreamAvailability,
};

#[cfg(test)]
pub(crate) use server_catalog::REQUIRED_SERVER_TYPES;
pub(crate) use server_catalog::enumerate_supported_servers;
pub(crate) use proxy_loop_guard::{ProxyLoopGuard, ProxyListenerBinding};
pub(crate) use request_tracker::{RequestGuard, RequestTracker};
pub use shutdown::{ListenerRegistration, ShutdownReceiver};
pub(crate) use shutdown::ShutdownCoordinator;
