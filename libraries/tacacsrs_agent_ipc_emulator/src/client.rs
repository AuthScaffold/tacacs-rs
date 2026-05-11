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
use crate::scenario::{CapturedIpcRequest, EmulatorScenario, RuleHitCount};

#[cfg(unix)]
const UDS_GRPC_CONNECT_URI: &str = "http://[::]:50051";

/// Client helper for the emulator mock-controller service.
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

    /// Replaces the active scenario and clears request/hit state.
    ///
    /// # Errors
    ///
    /// Returns an error if the scenario cannot be encoded or the controller RPC
    /// fails.
    pub async fn load_scenario(&mut self, scenario: &EmulatorScenario) -> anyhow::Result<()> {
        let scenario_json = serde_json::to_string(scenario).context("Failed to encode scenario")?;
        self.load_scenario_json(scenario_json).await
    }

    /// Replaces the active scenario from raw JSON and clears request/hit state.
    ///
    /// # Errors
    ///
    /// Returns an error if the controller rejects the JSON or the RPC fails.
    pub async fn load_scenario_json(&mut self, scenario_json: String) -> anyhow::Result<()> {
        self.inner
            .load_scenario(controller::LoadScenarioRequest { scenario_json })
            .await
            .context("Failed to load IPC emulator scenario")?;
        Ok(())
    }

    /// Clears captured requests and resets hit counts to zero.
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

    /// Fetches per-rule hit counts through the controller service.
    ///
    /// # Errors
    ///
    /// Returns an error if the controller RPC fails or returns malformed data.
    pub async fn rule_hits(&mut self) -> anyhow::Result<Vec<RuleHitCount>> {
        self.inner
            .get_rule_hit_counts(controller::GetRuleHitCountsRequest {})
            .await
            .context("Failed to fetch IPC emulator rule hit counts")?
            .into_inner()
            .hit_counts
            .into_iter()
            .map(RuleHitCount::try_from)
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
                .context("Failed to build Unix IPC emulator controller endpoint")?
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
                        "Failed to connect to IPC emulator controller socket {}",
                        path.display()
                    )
                })
        }
        IpcEndpoint::Tcp(address) => Endpoint::from_shared(format!("http://{address}"))
            .context("Failed to build TCP IPC emulator controller endpoint")?
            .connect()
            .await
            .with_context(|| format!("Failed to connect to IPC emulator controller {address}")),
    }
}
