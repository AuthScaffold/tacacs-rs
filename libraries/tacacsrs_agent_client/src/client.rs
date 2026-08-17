//! Local gRPC client helpers for communication with the central TACACS+ service.
//!
//! Callers give the client a local IPC endpoint. The client sends each request
//! through the protobuf/gRPC contract. It does not expose TACACS+ wire details.
//!
//! # Platform behavior
//!
//! | Platform | Transport | Notes |
//! |----------|-----------|-------|
//! | Linux / macOS | Unix domain socket | Default: `/run/tacacs/tacacs.sock` |
//! | Windows / other | Loopback TCP | Default: `127.0.0.1:9049` |
//!
//! [`ServiceClient`] holds a persistent gRPC [`tonic::transport::Channel`] that
//! is established during construction and reused for all requests. gRPC over
//! HTTP/2 multiplexes concurrent RPCs on one connection. Thus, callers can send
//! requests in parallel without a new connection for each request.

use anyhow::{Context, anyhow};
use tonic::transport::Channel;

use crate::ipc;
use crate::ipc::tacacs_agent_client::TacacsAgentClient;
use crate::protocol::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse, PapAuthenticationOperation, PapAuthenticationOperationResponse,
    ServiceError,
};
use crate::endpoint::connect_channel;
use crate::IpcEndpoint;

/// Convenience wrapper for making local IPC calls to the central service.
///
/// `ServiceClient` holds a persistent gRPC [`Channel`] that is established once
/// during construction and reuses it for all requests. gRPC over HTTP/2
/// multiplexes concurrent RPCs on one connection. Thus, callers can send
/// requests in parallel without a new connection for each request.
///
/// The type is [`Clone`] and [`Send`]; cloning is cheap because [`Channel`] is
/// reference-counted internally.
///
/// # Connection flow
///
/// ```text
/// Caller           ServiceClient        IpcEndpoint       Central Service
///   |                   |                   |                   |
///   | send_accounting() |                   |                   |
///   |------------------>|                   |                   |
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
/// # use tacacsrs_agent_client::{
/// #     AccountingOperation, IpcEndpoint, ServiceClient,
/// # };
/// # async fn example() -> anyhow::Result<()> {
/// let client = ServiceClient::connect(IpcEndpoint::default_local()).await?;
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
    /// The persistent gRPC channel shared across all requests.
    channel: Channel,
}

impl ServiceClient {
    /// Establishes a gRPC channel to the local IPC endpoint.
    ///
    /// The returned [`ServiceClient`] reuses the channel for all requests.
    ///
    /// On Unix, this connects over a Unix domain socket using `tonic`'s
    /// `connect_with_connector` to bridge `tokio::net::UnixStream` into the
    /// HTTP/2 transport. On other platforms it connects over loopback TCP.
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot establish the IPC connection.
    pub async fn connect(endpoint: IpcEndpoint) -> anyhow::Result<Self> {
        let channel = connect_channel(&endpoint).await?;
        Ok(Self { channel })
    }

    /// Sends a single accounting request to the local TACACS+ client service.
    ///
    /// Converts the domain [`AccountingOperation`] into a protobuf request. It
    /// sends the unary RPC over the persistent channel and converts the reply
    /// into the domain response type. Concurrent calls use the same HTTP/2
    /// connection.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The gRPC exchange fails at the transport level.
    /// - The service returns a structured [`ServiceError`], for example, when all
    ///   upstream TACACS+ servers are unavailable. The message includes the server
    ///   name, if known, and whether the caller can retry.
    pub async fn send_accounting(
        &self,
        request: AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        let mut client = TacacsAgentClient::new(self.channel.clone());
        let rpc_request: ipc::AccountingRequest = (&request).into();
        let reply = client
            .accounting(rpc_request)
            .await
            .context("Failed to run the accounting RPC")?
            .into_inner();

        match reply.result.context("Accounting RPC returned no result")? {
            ipc::accounting_reply::Result::Response(response) => {
                AccountingOperationResponse::from_proto(response)
            }
            ipc::accounting_reply::Result::Error(error) => {
                Err(service_error_as_anyhow("Accounting", &ServiceError::from_proto(error)))
            }
        }
    }

    /// Authenticates one user name and password with PAP.
    ///
    /// # Errors
    ///
    /// Returns an error when the gRPC exchange fails or the service returns a
    /// structured upstream error.
    pub async fn authenticate_pap(
        &self,
        request: PapAuthenticationOperation,
    ) -> anyhow::Result<PapAuthenticationOperationResponse> {
        let mut client = TacacsAgentClient::new(self.channel.clone());
        let reply = client
            .authenticate_pap(ipc::PapAuthenticationRequest::from(request))
            .await
            .context("Failed to run the PAP authentication RPC")?
            .into_inner();

        match reply
            .result
            .context("PAP authentication RPC returned no result")?
        {
            ipc::pap_authentication_reply::Result::Response(response) => {
                PapAuthenticationOperationResponse::from_proto(response)
            }
            ipc::pap_authentication_reply::Result::Error(error) => {
                Err(service_error_as_anyhow("PAP authentication", &ServiceError::from_proto(error)))
            }
        }
    }

    /// Sends a single authorization request to the local TACACS+ client service.
    ///
    /// Converts the domain [`AuthorizationOperation`] into a protobuf request.
    /// It sends the unary RPC over the persistent channel and converts the reply
    /// into the domain response type.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The gRPC exchange fails at the transport level.
    /// - The service returns a structured [`ServiceError`].
    pub async fn send_authorization(
        &self,
        request: AuthorizationOperation,
    ) -> anyhow::Result<AuthorizationOperationResponse> {
        let mut client = TacacsAgentClient::new(self.channel.clone());
        let rpc_request: ipc::AuthorizationRequest = (&request).into();
        let reply = client
            .authorization(rpc_request)
            .await
            .context("Failed to run the authorization RPC")?
            .into_inner();

        match reply
            .result
            .context("Authorization RPC returned no result")?
        {
            ipc::authorization_reply::Result::Response(response) => {
                AuthorizationOperationResponse::from_proto(response)
            }
            ipc::authorization_reply::Result::Error(error) => {
                Err(service_error_as_anyhow("Authorization", &ServiceError::from_proto(error)))
            }
        }
    }
}

fn service_error_as_anyhow(rpc_name: &str, error: &ServiceError) -> anyhow::Error {
    let retry_note = if error.retriable {
        " (retriable)"
    } else {
        ""
    };
    let server_note = error
        .server
        .as_ref()
        .map_or_else(String::new, |server| format!(" via {server}"));
    anyhow!("{rpc_name} RPC returned service error: {}{}{}", error.message, server_note, retry_note)
}
