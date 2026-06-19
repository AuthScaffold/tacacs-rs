//! Long-lived agent runtime lifecycle.
//!
//! This module owns startup validation, warm-up orchestration, datastore-driven
//! reload application, graceful shutdown signalling, and the public
//! [`TacacsClientService`] entry point. Local client protocol handling lives in
//! the client API service, while server selection and failover live in the
//! upstream manager.

mod client_service;
mod request_tracker;
mod server_catalog;
mod shutdown;

pub use client_service::TacacsClientService;

pub(crate) use server_catalog::{REQUIRED_SERVER_TYPES, enumerate_supported_servers};
pub(crate) use request_tracker::{RequestGuard, RequestTracker};
pub(crate) use shutdown::shutdown_signal;
