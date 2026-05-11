#![doc = include_str!("../README.md")]

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context};
#[cfg(unix)]
use http::Uri;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tacacsrs_agent_client::ipc;
use tacacsrs_agent_client::ipc::tacacs_agent_server::{TacacsAgent, TacacsAgentServer};
use tacacsrs_agent_client::{
    AccountingOperationResponse, AccountingResponseStatus, AuthorizationArg,
    AuthorizationOperationResponse, AuthorizationResponseStatus, IpcEndpoint, ServiceError,
};
use tokio::sync::oneshot;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};
#[cfg(unix)]
use tower::service_fn;

pub mod controller {
    #![allow(clippy::all, clippy::cargo, clippy::nursery, clippy::pedantic)]

    tonic::include_proto!("tacacsrs.agent.mock.v1");
}

use controller::tacacs_agent_mock_controller_client::TacacsAgentMockControllerClient as GeneratedControllerClient;
use controller::tacacs_agent_mock_controller_server::{
    TacacsAgentMockController, TacacsAgentMockControllerServer,
};

#[cfg(unix)]
const UDS_GRPC_CONNECT_URI: &str = "http://[::]:50051";

/// JSON-driven emulator for the local TACACS+ agent IPC service.
pub struct IpcEmulator {
    state: Arc<Mutex<EmulatorState>>,
    shutdown_sender: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    server_task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl IpcEmulator {
    /// Loads a JSON scenario file and binds on an ephemeral loopback TCP port.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the JSON cannot be parsed,
    /// or the emulator listener cannot be started.
    pub async fn from_file(path: impl AsRef<Path>) -> anyhow::Result<(Self, IpcEndpoint)> {
        Self::from_scenario(EmulatorScenario::from_file(path)?).await
    }

    /// Loads a JSON scenario file and binds on the provided endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the JSON cannot be parsed,
    /// or the provided endpoint cannot be bound.
    pub async fn from_file_at_endpoint(
        path: impl AsRef<Path>,
        endpoint: IpcEndpoint,
    ) -> anyhow::Result<(Self, IpcEndpoint)> {
        Self::from_scenario_at_endpoint(EmulatorScenario::from_file(path)?, endpoint).await
    }

    /// Starts an emulator on an ephemeral loopback TCP port.
    ///
    /// # Errors
    ///
    /// Returns an error if the emulator listener cannot be started.
    pub async fn from_scenario(scenario: EmulatorScenario) -> anyhow::Result<(Self, IpcEndpoint)> {
        Self::from_scenario_at_endpoint(
            scenario,
            IpcEndpoint::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        )
        .await
    }

    /// Starts an emulator on the provided IPC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint cannot be bound or is not a supported
    /// local IPC endpoint.
    pub async fn from_scenario_at_endpoint(
        scenario: EmulatorScenario,
        endpoint: IpcEndpoint,
    ) -> anyhow::Result<(Self, IpcEndpoint)> {
        match endpoint {
            IpcEndpoint::Tcp(address) => Self::serve_tcp(scenario, address).await,
            #[cfg(unix)]
            IpcEndpoint::Unix(path) => Self::serve_unix(scenario, path).await,
        }
    }

    /// Requests graceful shutdown and waits until the server exits.
    pub async fn shutdown(self) {
        send_shutdown(&self.shutdown_sender);
        let _ = self.server_task.await;
    }

    /// Waits until the server exits without requesting shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the server task panics or the gRPC server exits with
    /// an error.
    pub async fn wait(self) -> anyhow::Result<()> {
        self.server_task
            .await
            .context("IPC emulator server task panicked")?
    }

    /// Returns a snapshot of requests received by the emulator.
    #[must_use]
    pub fn captured_requests(&self) -> Vec<CapturedIpcRequest> {
        self.state
            .lock()
            .map_or_else(|_| Vec::new(), |state| state.captured_requests.clone())
    }

    /// Returns a snapshot of per-rule hit counts.
    #[must_use]
    pub fn rule_hits(&self) -> Vec<RuleHitCount> {
        self.state
            .lock()
            .map_or_else(|_| Vec::new(), |state| state.rule_hit_counts())
    }

    async fn serve_tcp(
        scenario: EmulatorScenario,
        address: SocketAddr,
    ) -> anyhow::Result<(Self, IpcEndpoint)> {
        if !address.ip().is_loopback() {
            bail!("TCP IPC emulator endpoint must be loopback-only: {address}");
        }
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("Failed to bind TCP IPC emulator endpoint {address}"))?;
        let local_addr = listener
            .local_addr()
            .context("Failed to inspect bound TCP endpoint")?;
        let incoming = TcpListenerStream::new(listener);
        let (emulator, shutdown_rx) = Self::new_with_shutdown(scenario);
        let agent = AgentService {
            state: Arc::clone(&emulator.state),
        };
        let controller = ControllerService {
            state: Arc::clone(&emulator.state),
            shutdown_sender: Arc::clone(&emulator.shutdown_sender),
        };
        let server_task = tokio::spawn(async move {
            Server::builder()
                .add_service(TacacsAgentServer::new(agent))
                .add_service(TacacsAgentMockControllerServer::new(controller))
                .serve_with_incoming_shutdown(incoming, shutdown_signal(shutdown_rx))
                .await
                .context("TCP IPC emulator server failed")
        });
        Ok((emulator.with_task(server_task), IpcEndpoint::Tcp(local_addr)))
    }

    #[cfg(unix)]
    async fn serve_unix(
        scenario: EmulatorScenario,
        path: PathBuf,
    ) -> anyhow::Result<(Self, IpcEndpoint)> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create IPC emulator socket directory {}", parent.display())
            })?;
        }
        if tokio::fs::try_exists(&path)
            .await
            .with_context(|| format!("Failed to inspect IPC emulator socket {}", path.display()))?
        {
            tokio::fs::remove_file(&path).await.with_context(|| {
                format!("Failed to remove stale IPC emulator socket {}", path.display())
            })?;
        }
        let listener = tokio::net::UnixListener::bind(&path).with_context(|| {
            format!("Failed to bind Unix IPC emulator socket {}", path.display())
        })?;
        let incoming = UnixListenerStream::new(listener);
        let cleanup_path = path.clone();
        let (emulator, shutdown_rx) = Self::new_with_shutdown(scenario);
        let agent = AgentService {
            state: Arc::clone(&emulator.state),
        };
        let controller = ControllerService {
            state: Arc::clone(&emulator.state),
            shutdown_sender: Arc::clone(&emulator.shutdown_sender),
        };
        let server_task = tokio::spawn(async move {
            let result = Server::builder()
                .add_service(TacacsAgentServer::new(agent))
                .add_service(TacacsAgentMockControllerServer::new(controller))
                .serve_with_incoming_shutdown(incoming, shutdown_signal(shutdown_rx))
                .await
                .context("Unix IPC emulator server failed");
            remove_unix_socket(&cleanup_path).await?;
            result
        });
        Ok((emulator.with_task(server_task), IpcEndpoint::Unix(path)))
    }

    fn new_with_shutdown(scenario: EmulatorScenario) -> (Self, oneshot::Receiver<()>) {
        let state = Arc::new(Mutex::new(EmulatorState::new(scenario)));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(async { Ok(()) });
        (
            Self {
                state,
                shutdown_sender: Arc::new(Mutex::new(Some(shutdown_tx))),
                server_task,
            },
            shutdown_rx,
        )
    }

    fn with_task(mut self, server_task: tokio::task::JoinHandle<anyhow::Result<()>>) -> Self {
        self.server_task.abort();
        self.server_task = server_task;
        self
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmulatorScenario {
    pub transactions: Vec<TransactionRule>,
}

impl EmulatorScenario {
    /// Reads and parses a JSON scenario file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read IPC emulator scenario {}", path.display()))?;
        serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse IPC emulator scenario {}", path.display()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRule {
    pub rpc: IpcRpc,
    #[serde(rename = "match")]
    pub match_fields: MatchFields,
    pub respond: EmulatorResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MatchFields {
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

impl MatchFields {
    /// Returns true when every configured field equals the request field value.
    #[must_use]
    pub fn matches(&self, request_fields: &BTreeMap<String, Value>) -> bool {
        self.fields
            .iter()
            .all(|(key, value)| request_fields.get(key) == Some(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IpcRpc {
    Accounting,
    Authorization,
}

impl fmt::Display for IpcRpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accounting => formatter.write_str("Accounting"),
            Self::Authorization => formatter.write_str("Authorization"),
        }
    }
}

impl std::str::FromStr for IpcRpc {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Accounting" => Ok(Self::Accounting),
            "Authorization" => Ok(Self::Authorization),
            _ => bail!("unsupported IPC RPC {value:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum EmulatorResponse {
    Response(ResponseBody),
    Error(ErrorBody),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseBody {
    pub server: String,
    pub status: String,
    #[serde(default)]
    pub server_message: String,
    #[serde(default)]
    pub data: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<ScenarioAuthorizationArg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub message: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub retriable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAuthorizationArg {
    pub name: String,
    pub mandatory: bool,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedIpcRequest {
    pub rpc: IpcRpc,
    pub fields: BTreeMap<String, Value>,
}

impl CapturedIpcRequest {
    fn request_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(&self.fields).context("Failed to encode captured IPC request")
    }
}

impl TryFrom<controller::CapturedIpcRequest> for CapturedIpcRequest {
    type Error = anyhow::Error;

    fn try_from(value: controller::CapturedIpcRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            rpc: value.rpc.parse()?,
            fields: serde_json::from_str(&value.request_json)
                .context("Failed to decode captured IPC request JSON")?,
        })
    }
}

impl TryFrom<&CapturedIpcRequest> for controller::CapturedIpcRequest {
    type Error = anyhow::Error;

    fn try_from(value: &CapturedIpcRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            rpc: value.rpc.to_string(),
            request_json: value.request_json()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleHitCount {
    pub index: usize,
    pub rpc: IpcRpc,
    pub hits: u64,
}

impl TryFrom<controller::RuleHitCount> for RuleHitCount {
    type Error = anyhow::Error;

    fn try_from(value: controller::RuleHitCount) -> Result<Self, Self::Error> {
        Ok(Self {
            index: usize::try_from(value.index).context("Rule hit index is out of range")?,
            rpc: value.rpc.parse()?,
            hits: value.hits,
        })
    }
}

impl TryFrom<&RuleHitCount> for controller::RuleHitCount {
    type Error = anyhow::Error;

    fn try_from(value: &RuleHitCount) -> Result<Self, Self::Error> {
        Ok(Self {
            index: u32::try_from(value.index).context("Rule hit index is out of range")?,
            rpc: value.rpc.to_string(),
            hits: value.hits,
        })
    }
}

struct EmulatorState {
    scenario: EmulatorScenario,
    captured_requests: Vec<CapturedIpcRequest>,
    hit_counts: Vec<u64>,
}

impl EmulatorState {
    fn new(scenario: EmulatorScenario) -> Self {
        let hit_counts = vec![0; scenario.transactions.len()];
        Self {
            scenario,
            captured_requests: Vec::new(),
            hit_counts,
        }
    }

    fn replace_scenario(&mut self, scenario: EmulatorScenario) {
        *self = Self::new(scenario);
    }

    fn reset(&mut self) {
        self.captured_requests.clear();
        self.hit_counts.fill(0);
    }

    fn rule_hit_counts(&self) -> Vec<RuleHitCount> {
        self.scenario
            .transactions
            .iter()
            .enumerate()
            .map(|(index, rule)| RuleHitCount {
                index,
                rpc: rule.rpc,
                hits: self.hit_counts[index],
            })
            .collect()
    }

    fn record_and_match(
        &mut self,
        rpc: IpcRpc,
        fields: &BTreeMap<String, Value>,
    ) -> Result<MatchedRule, Status> {
        self.captured_requests.push(CapturedIpcRequest {
            rpc,
            fields: fields.clone(),
        });
        let Some((index, rule)) = self
            .scenario
            .transactions
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.rpc == rpc && rule.match_fields.matches(fields))
        else {
            let request_json = serde_json::to_string(fields).map_err(|error| {
                Status::internal(format!(
                    "Failed to encode unmatched IPC request for diagnostics: {error}"
                ))
            })?;
            return Err(Status::not_found(format!(
                "IPC emulator has no {rpc} transaction rule matching {request_json}"
            )));
        };
        self.hit_counts[index] += 1;
        Ok(MatchedRule {
            response: rule.respond.clone(),
            delay_ms: rule.delay_ms,
        })
    }
}

struct MatchedRule {
    response: EmulatorResponse,
    delay_ms: Option<u64>,
}

#[derive(Clone)]
struct AgentService {
    state: Arc<Mutex<EmulatorState>>,
}

impl AgentService {
    async fn match_request(
        &self,
        rpc: IpcRpc,
        fields: BTreeMap<String, Value>,
    ) -> Result<MatchedRule, Status> {
        let matched = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?;
            state.record_and_match(rpc, &fields)?
        };
        if let Some(delay_ms) = matched.delay_ms {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        Ok(matched)
    }
}

#[tonic::async_trait]
impl TacacsAgent for AgentService {
    async fn accounting(
        &self,
        request: Request<ipc::AccountingRequest>,
    ) -> Result<Response<ipc::AccountingReply>, Status> {
        let fields = accounting_fields(&request.into_inner());
        let matched = self.match_request(IpcRpc::Accounting, fields).await?;
        match matched.response {
            EmulatorResponse::Response(response) => Ok(Response::new(ipc::AccountingReply {
                result: Some(ipc::accounting_reply::Result::Response(
                    accounting_response(response)?.into_proto(),
                )),
            })),
            EmulatorResponse::Error(error) => Ok(Response::new(ipc::AccountingReply {
                result: Some(ipc::accounting_reply::Result::Error(
                    service_error(error).into_proto(),
                )),
            })),
        }
    }

    async fn authorization(
        &self,
        request: Request<ipc::AuthorizationRequest>,
    ) -> Result<Response<ipc::AuthorizationReply>, Status> {
        let fields = authorization_fields(&request.into_inner());
        let matched = self.match_request(IpcRpc::Authorization, fields).await?;
        match matched.response {
            EmulatorResponse::Response(response) => Ok(Response::new(ipc::AuthorizationReply {
                result: Some(ipc::authorization_reply::Result::Response(
                    authorization_response(response)?.into_proto(),
                )),
            })),
            EmulatorResponse::Error(error) => Ok(Response::new(ipc::AuthorizationReply {
                result: Some(ipc::authorization_reply::Result::Error(
                    service_error(error).into_proto(),
                )),
            })),
        }
    }
}

#[derive(Clone)]
struct ControllerService {
    state: Arc<Mutex<EmulatorState>>,
    shutdown_sender: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

#[tonic::async_trait]
impl TacacsAgentMockController for ControllerService {
    async fn load_scenario(
        &self,
        request: Request<controller::LoadScenarioRequest>,
    ) -> Result<Response<controller::LoadScenarioReply>, Status> {
        let scenario = serde_json::from_str(&request.into_inner().scenario_json)
            .map_err(|error| Status::invalid_argument(format!("Invalid scenario JSON: {error}")))?;
        self.state
            .lock()
            .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?
            .replace_scenario(scenario);
        Ok(Response::new(controller::LoadScenarioReply {}))
    }

    async fn reset_state(
        &self,
        _request: Request<controller::ResetStateRequest>,
    ) -> Result<Response<controller::ResetStateReply>, Status> {
        self.state
            .lock()
            .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?
            .reset();
        Ok(Response::new(controller::ResetStateReply {}))
    }

    async fn get_captured_requests(
        &self,
        _request: Request<controller::GetCapturedRequestsRequest>,
    ) -> Result<Response<controller::GetCapturedRequestsReply>, Status> {
        let requests = self
            .state
            .lock()
            .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?
            .captured_requests
            .iter()
            .map(controller::CapturedIpcRequest::try_from)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(controller::GetCapturedRequestsReply { requests }))
    }

    async fn get_rule_hit_counts(
        &self,
        _request: Request<controller::GetRuleHitCountsRequest>,
    ) -> Result<Response<controller::GetRuleHitCountsReply>, Status> {
        let hit_counts = self
            .state
            .lock()
            .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?
            .rule_hit_counts()
            .iter()
            .map(controller::RuleHitCount::try_from)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(controller::GetRuleHitCountsReply { hit_counts }))
    }

    async fn shutdown(
        &self,
        _request: Request<controller::ShutdownRequest>,
    ) -> Result<Response<controller::ShutdownReply>, Status> {
        send_shutdown(&self.shutdown_sender);
        Ok(Response::new(controller::ShutdownReply {}))
    }
}

async fn shutdown_signal(shutdown_rx: oneshot::Receiver<()>) {
    let _ = shutdown_rx.await;
}

#[cfg(unix)]
async fn remove_unix_socket(path: &Path) -> anyhow::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("Failed to remove IPC emulator socket {}", path.display())),
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

fn send_shutdown(shutdown_sender: &Arc<Mutex<Option<oneshot::Sender<()>>>>) {
    if let Ok(mut sender) = shutdown_sender.lock() {
        if let Some(sender) = sender.take() {
            let _ = sender.send(());
        }
    }
}

fn accounting_fields(request: &ipc::AccountingRequest) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("user".to_owned(), json!(request.user)),
        ("port".to_owned(), json!(request.port)),
        ("remote_address".to_owned(), json!(request.remote_address)),
        ("command".to_owned(), json!(request.command)),
        ("command_arguments".to_owned(), json!(request.command_arguments)),
    ])
}

fn authorization_fields(request: &ipc::AuthorizationRequest) -> BTreeMap<String, Value> {
    let command = request
        .args
        .iter()
        .find(|arg| arg.name == "cmd")
        .map(|arg| arg.value.as_str());
    let command_arguments = request
        .args
        .iter()
        .filter(|arg| arg.name == "cmd-arg")
        .map(|arg| arg.value.clone())
        .collect::<Vec<_>>();
    BTreeMap::from([
        ("user".to_owned(), json!(request.user)),
        ("port".to_owned(), json!(request.port)),
        ("remote_address".to_owned(), json!(request.remote_address)),
        ("privilege_level".to_owned(), json!(request.privilege_level)),
        ("command".to_owned(), command.map_or(Value::Null, |value| json!(value))),
        ("command_arguments".to_owned(), json!(command_arguments)),
        (
            "args".to_owned(),
            Value::Array(
                request
                    .args
                    .iter()
                    .map(|arg| {
                        json!({
                            "name": arg.name,
                            "mandatory": arg.mandatory,
                            "value": arg.value,
                        })
                    })
                    .collect(),
            ),
        ),
    ])
}

fn accounting_response(response: ResponseBody) -> Result<AccountingOperationResponse, Status> {
    let status = match response.status.as_str() {
        "Success" => AccountingResponseStatus::Success,
        "Error" => AccountingResponseStatus::Error,
        "Follow" => AccountingResponseStatus::Follow,
        status => {
            return Err(Status::failed_precondition(format!(
                "Invalid Accounting response status {status:?}"
            )));
        }
    };
    Ok(AccountingOperationResponse {
        server: response.server,
        status,
        server_message: response.server_message,
        data: response.data,
    })
}

fn authorization_response(
    response: ResponseBody,
) -> Result<AuthorizationOperationResponse, Status> {
    let status = match response.status.as_str() {
        "PassAdd" => AuthorizationResponseStatus::PassAdd,
        "PassRepl" => AuthorizationResponseStatus::PassRepl,
        "Fail" => AuthorizationResponseStatus::Fail,
        "Error" => AuthorizationResponseStatus::Error,
        "Follow" => AuthorizationResponseStatus::Follow,
        status => {
            return Err(Status::failed_precondition(format!(
                "Invalid Authorization response status {status:?}"
            )));
        }
    };
    Ok(AuthorizationOperationResponse {
        server: response.server,
        status,
        server_message: response.server_message,
        args: response
            .args
            .into_iter()
            .map(|arg| AuthorizationArg::new(arg.name, arg.mandatory, arg.value))
            .collect(),
        data: response.data,
    })
}

fn service_error(error: ErrorBody) -> ServiceError {
    let mut service_error = ServiceError::new(error.message).retriable(error.retriable);
    if !error.server.is_empty() {
        service_error = service_error.with_server(error.server);
    }
    service_error
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tacacsrs_agent_client::{
        AccountingOperation, AuthorizationKey, AuthorizationOperation, ServiceClient,
    };

    use super::*;

    fn accounting_request(user: &str, command: &str) -> AccountingOperation {
        AccountingOperation {
            user: user.to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            command: command.to_owned(),
            command_arguments: vec!["brief".to_owned()],
        }
    }

    fn accounting_success_rule(user: &str, server: &str) -> TransactionRule {
        TransactionRule {
            rpc: IpcRpc::Accounting,
            match_fields: MatchFields {
                fields: BTreeMap::from([("user".to_owned(), json!(user))]),
            },
            respond: EmulatorResponse::Response(ResponseBody {
                server: server.to_owned(),
                status: "Success".to_owned(),
                server_message: String::new(),
                data: String::new(),
                args: Vec::new(),
            }),
            delay_ms: None,
        }
    }

    #[test]
    fn parses_json_scenario() {
        let scenario: EmulatorScenario = serde_json::from_str(
            r#"{
                "transactions": [{
                    "rpc": "Accounting",
                    "match": { "user": "admin", "command": "show" },
                    "respond": {
                        "type": "response",
                        "server": "tacacs-primary:49",
                        "status": "Success",
                        "server_message": "ok",
                        "data": ""
                    },
                    "delay_ms": 5
                }]
            }"#,
        )
        .expect("scenario should parse");

        assert_eq!(scenario.transactions.len(), 1);
        assert_eq!(scenario.transactions[0].rpc, IpcRpc::Accounting);
        assert_eq!(scenario.transactions[0].delay_ms, Some(5));
    }

    #[test]
    fn partial_matching_uses_only_present_fields() {
        let match_fields = MatchFields {
            fields: BTreeMap::from([("user".to_owned(), json!("admin"))]),
        };
        let request_fields = BTreeMap::from([
            ("user".to_owned(), json!("admin")),
            ("command".to_owned(), json!("show")),
        ]);

        assert!(match_fields.matches(&request_fields));
    }

    #[test]
    fn rules_are_evaluated_in_order() {
        let mut state = EmulatorState::new(EmulatorScenario {
            transactions: vec![
                accounting_success_rule("admin", "first"),
                accounting_success_rule("admin", "second"),
            ],
        });

        let fields = BTreeMap::from([("user".to_owned(), json!("admin"))]);
        let matched = state
            .record_and_match(IpcRpc::Accounting, &fields)
            .expect("rule should match");

        match matched.response {
            EmulatorResponse::Response(response) => assert_eq!(response.server, "first"),
            EmulatorResponse::Error(_) => panic!("expected response"),
        }
        assert_eq!(state.rule_hit_counts()[0].hits, 1);
        assert_eq!(state.rule_hit_counts()[1].hits, 0);
    }

    #[tokio::test]
    async fn delay_is_applied_before_response() {
        let scenario = EmulatorScenario {
            transactions: vec![TransactionRule {
                delay_ms: Some(25),
                ..accounting_success_rule("admin", "primary")
            }],
        };
        let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
            .await
            .expect("emulator should start");
        let client = ServiceClient::connect(endpoint)
            .await
            .expect("client should connect");

        let start = Instant::now();
        client
            .send_accounting(accounting_request("admin", "show"))
            .await
            .expect("request should succeed");

        assert!(start.elapsed() >= Duration::from_millis(25));
        emulator.shutdown().await;
    }

    #[tokio::test]
    async fn captures_requests_and_hit_counts() {
        let scenario = EmulatorScenario {
            transactions: vec![accounting_success_rule("admin", "primary")],
        };
        let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
            .await
            .expect("emulator should start");
        let client = ServiceClient::connect(endpoint)
            .await
            .expect("client should connect");

        client
            .send_accounting(accounting_request("admin", "show"))
            .await
            .expect("request should succeed");

        let captured = emulator.captured_requests();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].rpc, IpcRpc::Accounting);
        assert_eq!(captured[0].fields["user"], json!("admin"));
        assert_eq!(emulator.rule_hits()[0].hits, 1);
        emulator.shutdown().await;
    }

    #[tokio::test]
    async fn unmatched_request_returns_grpc_error() {
        let scenario = EmulatorScenario {
            transactions: vec![accounting_success_rule("admin", "primary")],
        };
        let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
            .await
            .expect("emulator should start");
        let client = ServiceClient::connect(endpoint)
            .await
            .expect("client should connect");

        let error = client
            .send_accounting(accounting_request("guest", "show"))
            .await
            .expect_err("unmatched request should fail");

        assert!(error
            .to_string()
            .contains("Failed to execute accounting RPC"));
        assert_eq!(emulator.captured_requests().len(), 1);
        assert_eq!(emulator.rule_hits()[0].hits, 0);
        emulator.shutdown().await;
    }

    #[tokio::test]
    async fn authorization_response_works_with_service_client() {
        let scenario = EmulatorScenario {
            transactions: vec![TransactionRule {
                rpc: IpcRpc::Authorization,
                match_fields: MatchFields {
                    fields: BTreeMap::from([("command".to_owned(), json!("show"))]),
                },
                respond: EmulatorResponse::Response(ResponseBody {
                    server: "primary".to_owned(),
                    status: "PassAdd".to_owned(),
                    server_message: String::new(),
                    data: String::new(),
                    args: Vec::new(),
                }),
                delay_ms: None,
            }],
        };
        let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
            .await
            .expect("emulator should start");
        let client = ServiceClient::connect(endpoint)
            .await
            .expect("client should connect");
        let request = AuthorizationOperation::builder("admin", 15)
            .port("tty0")
            .remote_address("127.0.0.1")
            .key_value(AuthorizationKey::Service, true, "shell")
            .key_value(AuthorizationKey::Cmd, true, "show")
            .build()
            .expect("authorization operation should build");

        let response = client
            .send_authorization(request)
            .await
            .expect("authorization request should succeed");

        assert_eq!(response.status, AuthorizationResponseStatus::PassAdd);
        assert_eq!(emulator.rule_hits()[0].hits, 1);
        emulator.shutdown().await;
    }

    #[tokio::test]
    async fn controller_can_reset_and_replace_state() {
        let scenario = EmulatorScenario {
            transactions: vec![accounting_success_rule("admin", "primary")],
        };
        let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
            .await
            .expect("emulator should start");
        let client = ServiceClient::connect(endpoint.clone())
            .await
            .expect("client should connect");
        let mut controller = MockControllerClient::connect(endpoint)
            .await
            .expect("controller should connect");

        client
            .send_accounting(accounting_request("admin", "show"))
            .await
            .expect("request should succeed");
        assert_eq!(controller.rule_hits().await.expect("hits should load")[0].hits, 1);

        controller
            .reset_state()
            .await
            .expect("reset should succeed");
        assert!(controller
            .captured_requests()
            .await
            .expect("captures should load")
            .is_empty());
        assert_eq!(controller.rule_hits().await.expect("hits should load")[0].hits, 0);

        controller
            .load_scenario(&EmulatorScenario {
                transactions: vec![accounting_success_rule("guest", "secondary")],
            })
            .await
            .expect("load should succeed");
        client
            .send_accounting(accounting_request("guest", "show"))
            .await
            .expect("new scenario should match");
        assert_eq!(controller.rule_hits().await.expect("hits should load")[0].hits, 1);
        emulator.shutdown().await;
    }
}
