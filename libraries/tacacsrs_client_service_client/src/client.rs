//! Local gRPC client helpers for talking to the central TACACS+ service.
//!
//! The client is intentionally lightweight: callers point it at a local IPC
//! endpoint and each request is carried through the protobuf/gRPC contract
//! without exposing TACACS+ wire details to the caller.

use anyhow::{Context, bail};
use http::Uri;
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use crate::ipc;
use crate::ipc::local_tacacs_client_service_client::LocalTacacsClientServiceClient;
use crate::protocol::{AccountingOperation, AccountingOperationResponse, ServiceError};
use crate::IpcEndpoint;

#[cfg(unix)]
const UDS_GRPC_CONNECT_URI: &str = "http://[::]:50051";

/// Convenience wrapper for making local IPC calls to the central service.
#[derive(Debug, Clone)]
pub struct ServiceClient {
    endpoint: IpcEndpoint,
}

impl ServiceClient {
    /// Creates a client targeting the given local IPC endpoint.
    #[must_use]
    pub fn new(endpoint: IpcEndpoint) -> Self {
        Self { endpoint }
    }

    /// Sends a single accounting request to the local TACACS+ client service.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPC connection fails, the gRPC exchange cannot
    /// be completed, or the service returns a structured error.
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
