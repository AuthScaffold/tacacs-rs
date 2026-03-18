//! Public configuration types for the local IPC listener and upstream failover.
//!
//! This module intentionally keeps parsing and defaults close to the config
//! structs so operators can see, in one place, how endpoint strings are
//! interpreted by the service runtime.

use std::time::Duration;

use tacacsrs_client_service_client::IpcEndpoint;

use crate::upstream::UpstreamConnectionOptions;

/// Configuration for the long-lived TACACS+ client service process.
///
/// The service consumes this once at startup. Validation that requires cross-
/// field context, such as ensuring at least one TACACS+ server is configured,
/// happens in [`crate::service::TacacsClientService::new`].
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Local IPC endpoint exposed to local consumers.
    ///
    /// Unix builds accept filesystem paths such as `/run/tacacs.sock`. All
    /// platforms accept a TCP socket address such as `127.0.0.1:9049` for
    /// developer workflows. Empty strings are rejected instead of defaulting.
    pub endpoint: IpcEndpoint,
    /// Ordered upstream TACACS+ servers. Index zero is the preferred server.
    pub server_addresses: Vec<String>,
    /// Shared options applied to each upstream TACACS+ connection.
    pub upstream: UpstreamConnectionOptions,
    /// How often the preferred server should be reprobed while failed over.
    pub preferred_probe_interval: Duration,
    #[cfg(unix)]
    /// File mode applied to the bound Unix socket path.
    pub socket_mode: u32,
}
