use anyhow::{bail, Context};

use crate::codec::{read_message, write_message};
use crate::protocol::{
    AccountingOperation, AccountingOperationResponse, ServiceRequest, ServiceResponse,
};
use crate::service::IpcEndpoint;

#[derive(Debug, Clone)]
pub struct ServiceClient {
    endpoint: IpcEndpoint,
}

impl ServiceClient {
    #[must_use]
    pub fn new(endpoint: IpcEndpoint) -> Self {
        Self { endpoint }
    }

    /// Sends a single accounting request to the local TACACS+ client service.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPC connection fails, the request/response
    /// exchange cannot be encoded or decoded, or the service returns an error.
    pub async fn send_accounting(
        &self,
        request: AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        match self
            .send_request(ServiceRequest::Accounting(request))
            .await?
        {
            ServiceResponse::Accounting(response) => Ok(response),
            ServiceResponse::Error(error) => {
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

    async fn send_request(&self, request: ServiceRequest) -> anyhow::Result<ServiceResponse> {
        match &self.endpoint {
            #[cfg(unix)]
            IpcEndpoint::Unix(path) => {
                let mut stream =
                    tokio::net::UnixStream::connect(path)
                        .await
                        .with_context(|| {
                            format!("Failed to connect to service socket {}", path.display())
                        })?;
                write_message(&mut stream, &request).await?;
                read_message(&mut stream).await
            }
            IpcEndpoint::Tcp(address) => {
                let mut stream = tokio::net::TcpStream::connect(address)
                    .await
                    .with_context(|| format!("Failed to connect to service endpoint {address}"))?;
                write_message(&mut stream, &request).await?;
                read_message(&mut stream).await
            }
        }
    }
}
