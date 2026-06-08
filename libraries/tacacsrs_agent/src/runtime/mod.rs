//! Long-lived agent runtime lifecycle.
//!
//! This module owns startup validation, warm-up orchestration, datastore-driven
//! reload application, graceful shutdown signalling, and the public
//! [`TacacsClientService`] entry point. Local IPC protocol handling lives in the
//! IPC layer, while server selection and failover live in the routing layer.

mod client_service;
mod server_catalog;
mod shutdown;

pub use client_service::TacacsClientService;

pub(crate) use server_catalog::{REQUIRED_SERVER_TYPES, enumerate_supported_servers};
pub(crate) use shutdown::shutdown_signal;
