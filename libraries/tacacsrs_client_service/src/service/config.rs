//! Public configuration types for the local IPC listener and upstream failover.
//!
//! This module intentionally keeps parsing and defaults close to the config
//! structs so operators can see, in one place, how endpoint strings are
//! interpreted by the service runtime.

use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, bail};

use crate::upstream::UpstreamConnectionOptions;

/// Local IPC endpoint used between local consumers and the central service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Unix domain socket endpoint used for Linux-style local IPC.
    #[cfg(unix)]
    Unix(PathBuf),
    /// Loopback TCP fallback used for non-Unix developer workflows.
    Tcp(SocketAddr),
}

impl IpcEndpoint {
    /// Returns the platform default local endpoint used when callers opt into
    /// the built-in default rather than supplying an explicit configuration
    /// value.
    ///
    /// This is not used implicitly by [`FromStr`]. Passing an empty string is
    /// still an error so configuration mistakes are surfaced early.
    #[must_use]
    pub fn default_local() -> Self {
        #[cfg(unix)]
        {
            Self::Unix(PathBuf::from("/run/tacacs.sock"))
        }

        #[cfg(not(unix))]
        {
            Self::Tcp(SocketAddr::from(([127, 0, 0, 1], 9049)))
        }
    }
}

impl FromStr for IpcEndpoint {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            bail!(
                "IPC endpoint cannot be empty; expected a Unix socket path or loopback host:port"
            );
        }

        #[cfg(unix)]
        if value.contains('/') {
            return Ok(Self::Unix(PathBuf::from(value)));
        }

        let socket_addr = value
            .parse::<SocketAddr>()
            .with_context(|| format!("Invalid IPC endpoint: {value}"))?;
        Ok(Self::Tcp(socket_addr))
    }
}

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

#[cfg(test)]
mod tests {
    use super::IpcEndpoint;

    #[test]
    fn test_empty_endpoint_string_is_rejected() {
        let error = ""
            .parse::<IpcEndpoint>()
            .expect_err("empty endpoint must fail");
        assert!(error.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_tcp_endpoint_string_parses() {
        let endpoint = "127.0.0.1:9049"
            .parse::<IpcEndpoint>()
            .expect("tcp endpoint should parse");
        assert!(matches!(endpoint, IpcEndpoint::Tcp(_)));
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_endpoint_string_parses() {
        let endpoint = "/run/tacacs.sock"
            .parse::<IpcEndpoint>()
            .expect("unix endpoint should parse");
        assert!(matches!(endpoint, IpcEndpoint::Unix(_)));
    }
}
