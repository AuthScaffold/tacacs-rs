//! Shared endpoint parsing for the local TACACS+ service IPC client/server.
//!
//! Both the [`ServiceClient`](crate::ServiceClient) and the service-side
//! listener use [`IpcEndpoint`] to describe the local communication channel.
//! Shared parsing makes sure that the client and server interpret endpoint
//! strings in the same way.
//!
//! # Endpoint formats
//!
//! | Input | Platform | Result |
//! |-------|----------|--------|
//! | `/run/tacacs/tacacs.sock` | Unix | `IpcEndpoint::Unix(PathBuf)` |
//! | `127.0.0.1:9049` | All | `IpcEndpoint::Tcp(SocketAddr)` |
//! | *(empty string)* | All | Error |

use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, bail};
#[cfg(unix)]
use http::Uri;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint};
#[cfg(unix)]
use tower::service_fn;

#[cfg(unix)]
const UDS_GRPC_CONNECT_URI: &str = "http://[::]:50051";

/// Local IPC endpoint used between local consumers and the central service.
///
/// On Unix, the preferred transport is a Unix domain socket. File permissions
/// control access, and this transport has no TCP overhead. Other platforms
/// accept a loopback TCP socket.
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
/// The parser rejects an empty string. This behavior reports configuration
/// errors instead of silently using a default.
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
    /// At bind time, the service makes sure that this address is loopback-only.
    /// This restriction prevents exposure on a network interface.
    Tcp(SocketAddr),
}

impl IpcEndpoint {
    /// Returns the default local IPC endpoint for this platform.
    ///
    /// | Platform | Default |
    /// |----------|---------|
    /// | Unix | `/run/tacacs/tacacs.sock` |
    /// | Non-Unix | `127.0.0.1:9049` |
    ///
    /// [`FromStr`] does not use this default. An empty string remains an error.
    #[must_use]
    pub fn default_local() -> Self {
        #[cfg(unix)]
        {
            Self::Unix(PathBuf::from("/run/tacacs/tacacs.sock"))
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
    /// On Unix, the parser treats a value that contains `/` as a Unix domain
    /// socket path. It parses all other values as `host:port` TCP socket
    /// addresses. It rejects empty strings.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            bail!(
                "IPC endpoint cannot be empty; expected a Unix domain socket path or loopback host:port"
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

/// Establishes a reusable gRPC channel to a local IPC endpoint.
///
/// # Errors
///
/// Returns an error when the endpoint cannot be represented as a gRPC
/// transport or the local socket cannot be reached.
pub async fn connect_channel(endpoint: &IpcEndpoint) -> anyhow::Result<Channel> {
    match endpoint {
        #[cfg(unix)]
        IpcEndpoint::Unix(path) => {
            let path = path.clone();
            let connect_path = path.clone();
            Endpoint::try_from(UDS_GRPC_CONNECT_URI)
                .context("Failed to build the Unix domain socket gRPC endpoint")?
                .connect_with_connector(service_fn(move |_: Uri| {
                    let path = connect_path.clone();
                    async move {
                        tokio::net::UnixStream::connect(path)
                            .await
                            .map(TokioIo::new)
                    }
                }))
                .await
                .with_context(|| {
                    format!("Failed to connect to service Unix domain socket {}", path.display())
                })
        }
        IpcEndpoint::Tcp(address) => Endpoint::from_shared(format!("http://{address}"))
            .context("Failed to build the TCP IPC gRPC endpoint")?
            .connect()
            .await
            .with_context(|| format!("Failed to connect to service IPC endpoint {address}")),
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
            .expect("TCP IPC endpoint must parse");
        assert!(matches!(endpoint, IpcEndpoint::Tcp(_)));
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_endpoint_string_parses() {
        let endpoint = "/run/tacacs/tacacs.sock"
            .parse::<IpcEndpoint>()
            .expect("Unix domain socket IPC endpoint must parse");
        assert!(matches!(endpoint, IpcEndpoint::Unix(_)));
    }
}
