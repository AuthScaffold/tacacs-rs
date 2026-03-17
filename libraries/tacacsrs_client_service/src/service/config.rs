use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;

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
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Local IPC endpoint exposed to local consumers.
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
