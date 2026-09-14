//! Long-lived agent runtime lifecycle.
//!
//! This module validates startup configuration and applies datastore reloads.
//! It also controls warm-up and graceful shutdown. The client API service
//! handles local client protocols. The upstream manager selects servers and
//! controls failover.

mod client_service;
mod health;
mod request_tracker;
mod server_catalog;
mod shutdown;

pub use client_service::TacacsClientService;
pub use health::{
    DatastoreState, DegradationReason, ListenerState, LocalCapabilityExclusion,
    RequiredLocalCapability, RuntimeHealthPublisher, RuntimeHealthSnapshot, RuntimeLifecycle,
    RuntimeService, UpstreamAvailability,
};

#[cfg(test)]
pub(crate) use server_catalog::REQUIRED_SERVER_TYPES;
pub(crate) use server_catalog::{
    OpenSslServerCapabilityValidator, ServerCapabilityValidator, admit_servers,
    enumerate_supported_servers,
};
pub(crate) use request_tracker::{RequestGuard, RequestTracker};
pub(crate) use shutdown::{ListenerRegistration, ShutdownCoordinator, ShutdownReceiver};
