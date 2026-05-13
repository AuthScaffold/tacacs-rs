use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgentServer;
use tacacsrs_agent_client::IpcEndpoint;
use tokio::sync::{oneshot, Mutex};
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use crate::controller::tacacs_agent_mock_controller_server::TacacsAgentMockControllerServer;
use crate::scenario::{CapturedIpcRequest, EmulatorScenario, RuleHitCount};
use crate::service::{send_shutdown, shutdown_signal, AgentService, ControllerService};
use crate::state::EmulatorState;

/// JSON-driven emulator for the local TACACS+ agent IPC service.
///
/// Call [`shutdown()`](Self::shutdown) for clean teardown. Dropping the
/// emulator without shutting down detaches the server task, which will
/// continue running until the Tokio runtime exits.
pub struct IpcEmulator {
    state: Arc<Mutex<EmulatorState>>,
    shutdown_sender: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    server_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl IpcEmulator {
    /// Loads a JSON scenario file and binds on an ephemeral loopback TCP port.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the JSON cannot be parsed,
    /// or the emulator listener cannot be started.
    pub async fn from_file(path: impl AsRef<Path>) -> anyhow::Result<(Self, IpcEndpoint)> {
        Self::from_scenario(EmulatorScenario::from_file_async(path).await?).await
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
        Self::from_scenario_at_endpoint(EmulatorScenario::from_file_async(path).await?, endpoint)
            .await
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
        send_shutdown(&self.shutdown_sender).await;
        if let Some(task) = self.server_task {
            let _ = task.await;
        }
    }

    /// Waits until the server exits without requesting shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the server task panics or the gRPC server exits with
    /// an error.
    pub async fn wait(self) -> anyhow::Result<()> {
        self.server_task
            .context("IPC emulator has no server task")?
            .await
            .context("IPC emulator server task panicked")?
    }

    /// Returns a snapshot of requests received by the emulator.
    #[must_use]
    pub async fn captured_requests(&self) -> Vec<CapturedIpcRequest> {
        self.state.lock().await.captured_requests()
    }

    /// Returns a snapshot of per-rule hit counts.
    #[must_use]
    pub async fn rule_hits(&self) -> Vec<RuleHitCount> {
        self.state.lock().await.rule_hit_counts()
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
        let (mut emulator, shutdown_rx) = Self::new_with_shutdown(scenario);
        let agent = AgentService {
            state: Arc::clone(&emulator.state),
        };
        let controller = ControllerService {
            state: Arc::clone(&emulator.state),
            shutdown_sender: Arc::clone(&emulator.shutdown_sender),
        };
        emulator.server_task = Some(tokio::spawn(async move {
            Server::builder()
                .add_service(TacacsAgentServer::new(agent))
                .add_service(TacacsAgentMockControllerServer::new(controller))
                .serve_with_incoming_shutdown(incoming, shutdown_signal(shutdown_rx))
                .await
                .context("TCP IPC emulator server failed")
        }));
        Ok((emulator, IpcEndpoint::Tcp(local_addr)))
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
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .with_context(|| {
                format!(
                    "Failed to restrict Unix IPC emulator socket permissions for {}",
                    path.display()
                )
            })?;
        let incoming = UnixListenerStream::new(listener);
        let cleanup_path = path.clone();
        let (mut emulator, shutdown_rx) = Self::new_with_shutdown(scenario);
        let agent = AgentService {
            state: Arc::clone(&emulator.state),
        };
        let controller = ControllerService {
            state: Arc::clone(&emulator.state),
            shutdown_sender: Arc::clone(&emulator.shutdown_sender),
        };
        emulator.server_task = Some(tokio::spawn(async move {
            let result = Server::builder()
                .add_service(TacacsAgentServer::new(agent))
                .add_service(TacacsAgentMockControllerServer::new(controller))
                .serve_with_incoming_shutdown(incoming, shutdown_signal(shutdown_rx))
                .await
                .context("Unix IPC emulator server failed");
            remove_unix_socket(&cleanup_path).await?;
            result
        }));
        Ok((emulator, IpcEndpoint::Unix(path)))
    }

    fn new_with_shutdown(scenario: EmulatorScenario) -> (Self, oneshot::Receiver<()>) {
        let state = Arc::new(Mutex::new(EmulatorState::new(scenario)));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        (
            Self {
                state,
                shutdown_sender: Arc::new(Mutex::new(Some(shutdown_tx))),
                server_task: None,
            },
            shutdown_rx,
        )
    }
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
