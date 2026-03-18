//! Public configuration types for the local IPC listener and upstream failover.
//!
//! This module intentionally keeps parsing and defaults close to the config
//! structs so operators can see, in one place, how endpoint strings are
//! interpreted by the service runtime.
//!
//! # Configuration flow
//!
//! The executable (e.g. `tacacs_client_service`) parses CLI flags or
//! environment variables into a [`ServiceConfig`], passes it to
//! [`TacacsClientService::new`](crate::TacacsClientService::new) for
//! validation, and then calls
//! [`serve`](crate::TacacsClientService::serve) to start the runtime.

use std::time::Duration;

use tacacsrs_client_service_client::IpcEndpoint;

use crate::upstream::UpstreamConnectionOptions;

/// Configuration for the long-lived TACACS+ client service process.
///
/// The service consumes this once at startup. Validation that requires cross-
/// field context, such as ensuring at least one TACACS+ server is configured,
/// happens in [`TacacsClientService::new`](crate::TacacsClientService::new).
///
/// # Required fields
///
/// - **`server_addresses`** — at least one upstream TACACS+ server must be
///   configured. The list order determines failover priority (index 0 is
///   preferred).
///
/// # Example
///
/// ```rust
/// # use std::time::Duration;
/// # use tacacsrs_client_service::{ServiceConfig, UpstreamConnectionOptions};
/// # use tacacsrs_client_service_client::IpcEndpoint;
/// let config = ServiceConfig {
///     endpoint: IpcEndpoint::default_local(),
///     server_addresses: vec!["tacacs-primary:49".into(), "tacacs-backup:49".into()],
///     upstream: UpstreamConnectionOptions::default(),
///     preferred_probe_interval: Duration::from_secs(30),
///     #[cfg(unix)]
///     socket_mode: 0o660,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Local IPC endpoint exposed to local consumers.
    ///
    /// Unix builds accept filesystem paths such as `/run/tacacs.sock`. All
    /// platforms accept a TCP socket address such as `127.0.0.1:9049` for
    /// developer workflows. Empty strings are rejected instead of defaulting.
    pub endpoint: IpcEndpoint,

    /// Ordered upstream TACACS+ servers. Index zero is the preferred server.
    ///
    /// The service attempts servers in order during failover and periodically
    /// probes the preferred server (index 0) to route traffic back to it once
    /// it recovers.
    pub server_addresses: Vec<String>,

    /// Shared options applied to each upstream TACACS+ connection.
    pub upstream: UpstreamConnectionOptions,

    /// How often the preferred server should be reprobed while failed over.
    ///
    /// Only effective when more than one server is configured. A shorter
    /// interval detects recovery faster at the cost of more probe connections.
    pub preferred_probe_interval: Duration,

    #[cfg(unix)]
    /// File mode applied to the bound Unix socket path.
    ///
    /// Typical values: `0o660` (owner + group) or `0o666` (world-accessible).
    pub socket_mode: u32,
}
