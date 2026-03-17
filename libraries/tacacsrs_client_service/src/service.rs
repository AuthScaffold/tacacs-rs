use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, RwLock};

use crate::codec::{read_message, write_message};
use crate::protocol::{ServiceError, ServiceRequest, ServiceResponse};
use crate::upstream::{
    NetworkUpstreamConnector, UpstreamConnection, UpstreamConnectionOptions, UpstreamConnector,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    #[cfg(unix)]
    Unix(PathBuf),
    Tcp(SocketAddr),
}

impl IpcEndpoint {
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

    fn from_str(value: &str) -> Result<Self, Self::Err> {
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

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub endpoint: IpcEndpoint,
    pub server_addresses: Vec<String>,
    pub upstream: UpstreamConnectionOptions,
    pub preferred_probe_interval: Duration,
}

pub struct TacacsClientService {
    config: ServiceConfig,
    state: Arc<ServiceState>,
}

impl TacacsClientService {
    /// Builds a TACACS+ client service with persistent upstream connections and
    /// ordered failover state.
    ///
    /// # Errors
    ///
    /// Returns an error if no upstream TACACS+ servers are configured.
    pub fn new(config: ServiceConfig) -> anyhow::Result<Self> {
        if config.server_addresses.is_empty() {
            bail!("At least one TACACS+ server address must be configured");
        }

        let connector: Arc<dyn UpstreamConnector> =
            Arc::new(NetworkUpstreamConnector::new(config.upstream.clone()));
        let state = Arc::new(ServiceState::new(
            config.server_addresses.clone(),
            connector,
            config.preferred_probe_interval,
        ));

        Ok(Self { config, state })
    }

    #[cfg(test)]
    fn new_with_connector(
        config: ServiceConfig,
        connector: Arc<dyn UpstreamConnector>,
    ) -> anyhow::Result<Self> {
        if config.server_addresses.is_empty() {
            bail!("At least one TACACS+ server address must be configured");
        }

        let state = Arc::new(ServiceState::new(
            config.server_addresses.clone(),
            connector,
            config.preferred_probe_interval,
        ));

        Ok(Self { config, state })
    }

    /// Starts serving local IPC requests until the process is terminated.
    ///
    /// # Errors
    ///
    /// Returns an error if the IPC listener cannot be created or if the local
    /// endpoint configuration is invalid for the current platform.
    pub async fn serve(self) -> anyhow::Result<()> {
        self.state.warm_connections().await;
        let _probe_task =
            (self.state.server_count() > 1).then(|| self.state.spawn_preferred_probe());

        match &self.config.endpoint {
            #[cfg(unix)]
            IpcEndpoint::Unix(path) => self.serve_unix(path).await,
            IpcEndpoint::Tcp(address) => self.serve_tcp(*address).await,
        }
    }

    #[cfg(unix)]
    async fn serve_unix(&self, path: &PathBuf) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create socket directory {}", parent.display())
            })?;
        }

        if tokio::fs::try_exists(path)
            .await
            .with_context(|| format!("Failed to inspect socket path {}", path.display()))?
        {
            tokio::fs::remove_file(path)
                .await
                .with_context(|| format!("Failed to remove existing socket {}", path.display()))?;
        }

        let listener = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("Failed to bind Unix socket {}", path.display()))?;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set permissions on socket {}", path.display()))?;

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .context("Failed to accept Unix socket connection")?;
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                if let Err(error) = state.handle_client(stream).await {
                    log::error!("IPC client handling failed: {error}");
                }
            });
        }
    }

    async fn serve_tcp(&self, address: SocketAddr) -> anyhow::Result<()> {
        if !address.ip().is_loopback() {
            bail!("TCP IPC endpoint must be loopback-only: {address}");
        }

        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("Failed to bind TCP IPC endpoint {address}"))?;

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .context("Failed to accept TCP IPC connection")?;
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                if let Err(error) = state.handle_client(stream).await {
                    log::error!("IPC client handling failed: {error}");
                }
            });
        }
    }
}

struct ServiceState {
    servers: Vec<ServerState>,
    connector: Arc<dyn UpstreamConnector>,
    active_index: Mutex<usize>,
    preferred_probe_interval: Duration,
}

struct ServerState {
    address: String,
    connection: RwLock<Option<Arc<dyn UpstreamConnection>>>,
}

struct BoundServer {
    index: usize,
    connection: Arc<dyn UpstreamConnection>,
}

impl ServiceState {
    fn new(
        server_addresses: Vec<String>,
        connector: Arc<dyn UpstreamConnector>,
        preferred_probe_interval: Duration,
    ) -> Self {
        Self {
            servers: server_addresses
                .into_iter()
                .map(|address| ServerState {
                    address,
                    connection: RwLock::new(None),
                })
                .collect(),
            connector,
            active_index: Mutex::new(0),
            preferred_probe_interval,
        }
    }

    async fn warm_connections(&self) {
        for index in 0..self.servers.len() {
            if let Err(error) = self.ensure_connection(index).await {
                log::warn!(
                    "Initial connection attempt to {} failed: {error}",
                    self.servers[index].address
                );
            }
        }
    }

    fn server_count(&self) -> usize {
        self.servers.len()
    }

    fn spawn_preferred_probe(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(state.preferred_probe_interval).await;

                if state.servers.len() <= 1 {
                    continue;
                }

                let active_index = *state.active_index.lock().await;
                if active_index == 0 {
                    continue;
                }

                match state.ensure_connection(0).await {
                    Ok(connection) if connection.is_usable_for_new_sessions().await => {
                        log::info!(
                            "Preferred TACACS+ server {} recovered; routing new sessions back to it",
                            connection.server_address()
                        );
                        *state.active_index.lock().await = 0;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        log::debug!("Preferred TACACS+ server probe failed: {error}");
                    }
                }
            }
        })
    }

    async fn handle_client<S>(&self, mut stream: S) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let request: ServiceRequest = read_message(&mut stream).await?;
        let response = match self.bind_server_for_new_session().await {
            Ok(bound_server) => self.execute_request(bound_server, request).await,
            Err(error) => {
                ServiceResponse::Error(ServiceError::new(error.to_string()).retriable(true))
            }
        };

        write_message(&mut stream, &response).await
    }

    async fn execute_request(
        &self,
        bound_server: BoundServer,
        request: ServiceRequest,
    ) -> ServiceResponse {
        match request {
            ServiceRequest::Accounting(accounting) => {
                match bound_server.connection.send_accounting(&accounting).await {
                    Ok(response) => ServiceResponse::Accounting(response),
                    Err(error) => {
                        self.note_failure(bound_server.index).await;
                        ServiceResponse::Error(
                            ServiceError::new(error.to_string())
                                .with_server(bound_server.connection.server_address())
                                .retriable(true),
                        )
                    }
                }
            }
        }
    }

    async fn bind_server_for_new_session(&self) -> anyhow::Result<BoundServer> {
        let start_index = *self.active_index.lock().await;

        for offset in 0..self.servers.len() {
            let index = (start_index + offset) % self.servers.len();
            match self.ensure_connection(index).await {
                Ok(connection) if connection.is_usable_for_new_sessions().await => {
                    *self.active_index.lock().await = index;
                    return Ok(BoundServer { index, connection });
                }
                Ok(_) => {
                    self.note_failure(index).await;
                }
                Err(error) => {
                    log::warn!(
                        "TACACS+ server {} is non-responsive: {error}",
                        self.servers[index].address
                    );
                    self.note_failure(index).await;
                }
            }
        }

        bail!("No responsive TACACS+ servers are currently available")
    }

    async fn ensure_connection(&self, index: usize) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        if let Some(existing) = self.servers[index].connection.read().await.clone() {
            if existing.is_usable_for_new_sessions().await {
                return Ok(existing);
            }
        }

        let connection = self.connector.connect(&self.servers[index].address).await?;
        *self.servers[index].connection.write().await = Some(Arc::clone(&connection));
        Ok(connection)
    }

    async fn note_failure(&self, index: usize) {
        *self.servers[index].connection.write().await = None;
        let mut active_index = self.active_index.lock().await;
        if *active_index == index {
            *active_index = (index + 1) % self.servers.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ServiceClient;
    use crate::protocol::{AccountingOperation, AccountingOperationResponse};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct FakeConnection {
        address: String,
        usable: AtomicBool,
        fail_next_request: AtomicBool,
    }

    #[async_trait]
    impl UpstreamConnection for FakeConnection {
        fn server_address(&self) -> &str {
            &self.address
        }

        async fn is_usable_for_new_sessions(&self) -> bool {
            self.usable.load(Ordering::Relaxed)
        }

        async fn send_accounting(
            &self,
            _request: &crate::protocol::AccountingOperation,
        ) -> anyhow::Result<AccountingOperationResponse> {
            if self.fail_next_request.swap(false, Ordering::Relaxed) {
                self.usable.store(false, Ordering::Relaxed);
                anyhow::bail!("simulated failure from {}", self.address);
            }

            Ok(AccountingOperationResponse {
                server: self.address.clone(),
                status_code: 1,
                status_name: "Success".to_owned(),
                server_message: format!("handled by {}", self.address),
                data: String::new(),
            })
        }
    }

    #[derive(Debug)]
    struct FakeConnector {
        connections: HashMap<String, Arc<FakeConnection>>,
    }

    #[async_trait]
    impl UpstreamConnector for FakeConnector {
        async fn connect(&self, address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
            let connection = self
                .connections
                .get(address)
                .with_context(|| format!("missing fake connection for {address}"))?;

            if !connection.usable.load(Ordering::Relaxed) {
                anyhow::bail!("{address} is currently down");
            }

            Ok(Arc::clone(connection) as Arc<dyn UpstreamConnection>)
        }
    }

    fn test_endpoint(socket_name: &str) -> IpcEndpoint {
        #[cfg(unix)]
        {
            let unique = format!(
                "{}-{}-{}.sock",
                socket_name,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            IpcEndpoint::Unix(std::env::temp_dir().join(unique))
        }

        #[cfg(not(unix))]
        {
            IpcEndpoint::Tcp(SocketAddr::from(([127, 0, 0, 1], 19049)))
        }
    }

    #[tokio::test]
    async fn test_server_selection_wraps_to_later_server() {
        let first = Arc::new(FakeConnection {
            address: "server-a:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let second = Arc::new(FakeConnection {
            address: "server-b:49".to_owned(),
            usable: AtomicBool::new(false),
            fail_next_request: AtomicBool::new(false),
        });
        let third = Arc::new(FakeConnection {
            address: "server-c:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector {
            connections: HashMap::from([
                (first.address.clone(), Arc::clone(&first)),
                (second.address.clone(), Arc::clone(&second)),
                (third.address.clone(), Arc::clone(&third)),
            ]),
        });

        let state = ServiceState::new(
            vec![
                first.address.clone(),
                second.address.clone(),
                third.address.clone(),
            ],
            connector,
            Duration::from_millis(25),
        );

        let bound = state.bind_server_for_new_session().await.unwrap();
        assert_eq!(bound.connection.server_address(), "server-c:49");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_unix_socket_failover_and_preferred_recovery() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let secondary = Arc::new(FakeConnection {
            address: "secondary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });

        let connector = Arc::new(FakeConnector {
            connections: HashMap::from([
                (primary.address.clone(), Arc::clone(&primary)),
                (secondary.address.clone(), Arc::clone(&secondary)),
            ]),
        });

        let endpoint = test_endpoint("tacacs-service-test");
        let config = ServiceConfig {
            endpoint: endpoint.clone(),
            server_addresses: vec![primary.address.clone(), secondary.address.clone()],
            upstream: UpstreamConnectionOptions::default(),
            preferred_probe_interval: Duration::from_millis(50),
        };

        let service = TacacsClientService::new_with_connector(config, connector).unwrap();
        let service_task = tokio::spawn(async move { service.serve().await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = ServiceClient::new(endpoint.clone());
        let request = AccountingOperation {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned()],
            custom_flag_1: false,
            custom_flag_2: false,
            session_id: None,
        };

        let first = client.send_accounting(request.clone()).await.unwrap();
        assert_eq!(first.server, "primary:49");

        primary.fail_next_request.store(true, Ordering::Relaxed);
        let failure = client.send_accounting(request.clone()).await.unwrap_err();
        assert!(failure
            .to_string()
            .contains("simulated failure from primary:49"));

        let second = client.send_accounting(request.clone()).await.unwrap();
        assert_eq!(second.server, "secondary:49");

        primary.usable.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(120)).await;

        let third = client.send_accounting(request).await.unwrap();
        assert_eq!(third.server, "primary:49");

        service_task.abort();
        let _ = service_task.await;

        if let IpcEndpoint::Unix(path) = endpoint {
            let _ = tokio::fs::remove_file(path).await;
        }
    }
}
