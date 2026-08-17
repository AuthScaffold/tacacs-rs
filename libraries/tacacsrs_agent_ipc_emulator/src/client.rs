use anyhow::Context;
#[cfg(unix)]
use http::Uri;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
use tacacsrs_agent_client::IpcEndpoint;
use tonic::transport::{Channel, Endpoint};
#[cfg(unix)]
use tower::service_fn;

use crate::controller;
use crate::controller::tacacs_agent_mock_controller_client::TacacsAgentMockControllerClient as GeneratedControllerClient;
use crate::policy::{CapturedIpcRequest, EmulatorPolicy};

#[cfg(unix)]
const UDS_GRPC_CONNECT_URI: &str = "http://[::]:50051";

/// Client for the emulator mock-controller service.
pub struct MockControllerClient {
    inner: GeneratedControllerClient<Channel>,
}

impl MockControllerClient {
    /// Connects to the mock-controller service at an emulator endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the gRPC channel cannot be established.
    pub async fn connect(endpoint: IpcEndpoint) -> anyhow::Result<Self> {
        Ok(Self {
            inner: GeneratedControllerClient::new(connect_channel(endpoint).await?),
        })
    }

    /// Replaces the active policy and clears captured requests.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy data cannot be encoded or the controller
    /// RPC fails.
    pub async fn load_policy(&mut self, policy: &EmulatorPolicy) -> anyhow::Result<()> {
        let data_json = serde_json::to_string(&policy.data)
            .context("Failed to encode IPC emulator policy data")?;
        self.load_policy_rego(policy.rego.clone(), data_json).await
    }

    /// Replaces the active policy with raw Rego source and JSON data.
    ///
    /// An empty `data_json` string is treated as no policy data.
    ///
    /// # Errors
    ///
    /// Returns an error if the controller rejects the policy or the RPC fails.
    pub async fn load_policy_rego(
        &mut self,
        policy_rego: String,
        data_json: String,
    ) -> anyhow::Result<()> {
        self.inner
            .load_policy(controller::LoadPolicyRequest {
                policy_rego,
                data_json,
            })
            .await
            .context("Failed to load IPC emulator policy")?;
        Ok(())
    }

    /// Clears captured requests.
    ///
    /// # Errors
    ///
    /// Returns an error if the controller RPC fails.
    pub async fn reset_state(&mut self) -> anyhow::Result<()> {
        self.inner
            .reset_state(controller::ResetStateRequest {})
            .await
            .context("Failed to reset IPC emulator state")?;
        Ok(())
    }

    /// Fetches captured requests through the controller service.
    ///
    /// # Errors
    ///
    /// Returns an error if the controller RPC fails or returns malformed data.
    pub async fn captured_requests(&mut self) -> anyhow::Result<Vec<CapturedIpcRequest>> {
        self.inner
            .get_captured_requests(controller::GetCapturedRequestsRequest {})
            .await
            .context("Failed to fetch IPC emulator captured requests")?
            .into_inner()
            .requests
            .into_iter()
            .map(CapturedIpcRequest::try_from)
            .collect()
    }

    /// Requests graceful emulator shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the controller RPC fails.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.inner
            .shutdown(controller::ShutdownRequest {})
            .await
            .context("Failed to shut down IPC emulator")?;
        Ok(())
    }
}

async fn connect_channel(endpoint: IpcEndpoint) -> anyhow::Result<Channel> {
    match endpoint {
        #[cfg(unix)]
        IpcEndpoint::Unix(path) => {
            let connect_path = path.clone();
            Endpoint::try_from(UDS_GRPC_CONNECT_URI)
                .context("Failed to build the emulator controller Unix domain socket endpoint")?
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
                    format!(
                        "Failed to connect to emulator controller Unix domain socket {}",
                        path.display()
                    )
                })
        }
        IpcEndpoint::Tcp(address) => Endpoint::from_shared(format!("http://{address}"))
            .context("Failed to build the emulator controller TCP IPC endpoint")?
            .connect()
            .await
            .with_context(|| {
                format!("Failed to connect to emulator controller IPC endpoint {address}")
            }),
    }
}
