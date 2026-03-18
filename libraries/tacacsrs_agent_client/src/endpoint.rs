//! Shared endpoint parsing for the local TACACS+ service IPC client/server.
//!
//! Both the [`ServiceClient`](crate::ServiceClient) and the service-side
//! listener use [`IpcEndpoint`] to describe the local communication channel.
//! The same parsing logic is shared so the client and server always agree on
//! how endpoint strings are interpreted.
//!
//! # Endpoint formats
//!
//! | Input | Platform | Result |
//! |-------|----------|--------|
//! | `/run/tacacs.sock` | Unix | `IpcEndpoint::Unix(PathBuf)` |
//! | `127.0.0.1:9049` | All | `IpcEndpoint::Tcp(SocketAddr)` |
//! | *(empty string)* | All | Error |

use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, bail};

/// Local IPC endpoint used between local consumers and the central service.
///
/// On Unix, the preferred transport is a Unix domain socket for security (file
/// permissions) and performance (no TCP overhead). On non-Unix platforms (or
/// for developer convenience) a loopback TCP socket is accepted instead.
///
/// # Parsing
///
/// `IpcEndpoint` implements [`FromStr`] so it can be used directly with
/// command-line argument parsers. On Unix, any value containing `/` is treated
/// as a socket path; otherwise the value is parsed as a `SocketAddr`.
///
/// ```
/// # use tacacsrs_agent_client::IpcEndpoint;
/// let tcp: IpcEndpoint = "127.0.0.1:9049".parse().unwrap();
/// assert!(matches!(tcp, IpcEndpoint::Tcp(_)));
/// ```
///
/// Empty strings are explicitly rejected so configuration mistakes are
/// surfaced early rather than silently falling back to a default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Unix domain socket endpoint used for Linux-style local IPC.
    ///
    /// Preferred on production Linux deployments because filesystem permissions
    /// control access and there is no TCP overhead.
    #[cfg(unix)]
    Unix(PathBuf),

    /// Loopback TCP fallback used for non-Unix developer workflows.
    ///
    /// The service enforces that the address is loopback-only at bind time to
    /// prevent accidental exposure on a network interface.
    Tcp(SocketAddr),
}

impl IpcEndpoint {
    /// Returns the platform default local endpoint used when callers opt into
    /// the built-in default rather than supplying an explicit configuration
    /// value.
    ///
    /// | Platform | Default |
    /// |----------|---------|
    /// | Unix | `/run/tacacs.sock` |
    /// | Non-Unix | `127.0.0.1:9049` |
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

    /// Parses an IPC endpoint string.
    ///
    /// On Unix, values containing `/` are interpreted as filesystem paths for
    /// Unix domain sockets. All other values are parsed as `host:port` TCP
    /// socket addresses. Empty strings are rejected.
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
