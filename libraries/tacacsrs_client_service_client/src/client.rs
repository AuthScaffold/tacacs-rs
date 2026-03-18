//! Local gRPC client helpers for talking to the central TACACS+ service.
//!
//! The client is intentionally lightweight: callers point it at a local IPC
//! endpoint and each request is carried through the protobuf/gRPC contract
//! without exposing TACACS+ wire details to the caller.
//!
//! # Platform behavior
//!
//! | Platform | Transport | Notes |
//! |----------|-----------|-------|
//! | Linux / macOS | Unix domain socket | Default: `/run/tacacs.sock` |
//! | Windows / other | Loopback TCP | Default: `127.0.0.1:9049` |
//!
//! Each [`ServiceClient::send_accounting`] call opens a fresh gRPC channel.
//! This matches the service's one-request-per-IPC-connection model and keeps
//! the client stateless and cheap to construct.

use anyhow::{Context, bail};
#[cfg(unix)]
use http::Uri;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint};
#[cfg(unix)]
use tower::service_fn;

use crate::ipc;
use crate::ipc::local_tacacs_client_service_client::LocalTacacsClientServiceClient;
use crate::protocol::{AccountingOperation, AccountingOperationResponse, ServiceError};
use crate::IpcEndpoint;

#[cfg(unix)]
const UDS_GRPC_CONNECT_URI: &str = "http://[::]:50051";

/// Convenience wrapper for making local IPC calls to the central service.
///
/// `ServiceClient` is intentionally stateless. Each call opens a new gRPC
/// channel, issues exactly one unary RPC, and drops the channel. Construction
/// is cheap and the type is both [`Clone`] and [`Send`].
///
/// # Connection flow
///
/// ```text
/// Caller           ServiceClient        IpcEndpoint       Central Service
///   |                   |                   |                   |
///   | send_accounting() |                   |                   |
///   |------------------>|                   |                   |
///   |                   | resolve endpoint  |                   |
///   |                   |------------------>|                   |
///   |                   |                   |                   |
///   |                   | gRPC Accounting(request)              |
///   |                   |-------------------------------------->|
///   |                   |                                       |
///   |                   |              AccountingReply          |
///   |                   |<--------------------------------------|
///   |                   |                                       |
///   |   Ok(response)    |                                       |
///   |   or Err(error)   |                                       |
///   |<------------------|                                       |
/// ```
///
/// # Examples
///
/// ```rust,no_run
/// # use tacacsrs_client_service_client::{
/// #     AccountingOperation, IpcEndpoint, ServiceClient,
/// # };
/// # async fn example() -> anyhow::Result<()> {
/// let client = ServiceClient::new(IpcEndpoint::default_local());
///
/// let response = client
///     .send_accounting(AccountingOperation {
///         user: "admin".into(),
///         port: "tty0".into(),
///         remote_address: "10.0.0.1".into(),
///         command: "show".into(),
///         command_arguments: vec!["users".into()],
///     })
///     .await?;
///
/// println!("Handled by {} → {:?}", response.server, response.status);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ServiceClient {
    /// The local IPC endpoint used when connecting to the central service.
    endpoint: IpcEndpoint,
}

impl ServiceClient {
    /// Creates a client targeting the given local IPC endpoint.
    ///
    /// No connection is established until a request method is called.
    #[must_use]
    pub fn new(endpoint: IpcEndpoint) -> Self {
        Self { endpoint }
    }

    /// Sends a single accounting request to the local TACACS+ client service.
    ///
    /// The call opens a fresh gRPC channel, converts the domain
    /// [`AccountingOperation`] into a protobuf request, issues the unary RPC,
    /// and converts the reply back into the domain response type.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The IPC connection cannot be established (socket missing, service not
    ///   running, etc.).
    /// - The gRPC exchange fails at the transport level.
    /// - The service returns a structured [`ServiceError`] (e.g. all upstream
    ///   TACACS+ servers are unavailable). The error message includes the
    ///   server name (if known) and whether the caller should retry.
    pub async fn send_accounting(
        &self,
        request: AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        let mut client = self.connect().await?;
        let rpc_request: ipc::AccountingRequest = (&request).into();
        let reply = client
            .accounting(rpc_request)
            .await
            .context("Failed to execute accounting RPC")?
            .into_inner();

        match reply.result.context("Accounting RPC returned no result")? {
            ipc::accounting_reply::Result::Response(response) => {
                AccountingOperationResponse::from_proto(response)
            }
            ipc::accounting_reply::Result::Error(error) => {
                let error = ServiceError::from_proto(error);
                let retry_note = if error.retriable {
                    " (retriable)"
                } else {
                    ""
                };
                let server_note = error
                    .server
                    .as_ref()
                    .map_or_else(String::new, |server| format!(" via {server}"));
                bail!("{}{}{}", error.message, server_note, retry_note);
            }
        }
    }

    /// Opens a gRPC channel to the configured IPC endpoint.
    ///
    /// On Unix, this connects over a Unix domain socket using `tonic`'s
    /// `connect_with_connector` to bridge `tokio::net::UnixStream` into the
    /// HTTP/2 transport. On other platforms it connects over loopback TCP.
    async fn connect(&self) -> anyhow::Result<LocalTacacsClientServiceClient<Channel>> {
        match &self.endpoint {
            #[cfg(unix)]
            IpcEndpoint::Unix(path) => {
                let path = path.clone();
                let connect_path = path.clone();
                let channel = Endpoint::try_from(UDS_GRPC_CONNECT_URI)
                    .context("Failed to build Unix IPC gRPC endpoint")?
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
                        format!("Failed to connect to service socket {}", path.display())
                    })?;
                Ok(LocalTacacsClientServiceClient::new(channel))
            }
            IpcEndpoint::Tcp(address) => {
                let channel = Endpoint::from_shared(format!("http://{address}"))
                    .context("Failed to build TCP IPC gRPC endpoint")?
                    .connect()
                    .await
                    .with_context(|| format!("Failed to connect to service endpoint {address}"))?;
                Ok(LocalTacacsClientServiceClient::new(channel))
            }
        }
    }
}
