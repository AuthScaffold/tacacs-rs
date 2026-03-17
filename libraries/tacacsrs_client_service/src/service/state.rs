use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::bail;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, RwLock};

use crate::codec::{read_message, write_message};
use crate::protocol::{ServiceError, ServiceRequest, ServiceResponse};
use crate::upstream::{UpstreamConnection, UpstreamConnector};

pub(super) struct ServiceState {
    servers: Vec<ServerState>,
    connector: Arc<dyn UpstreamConnector>,
    active_index: RwLock<usize>,
    preferred_probe_interval: Duration,
    client_tracker: Arc<ClientTracker>,
}

struct ServerState {
    address: String,
    connection: RwLock<Option<Arc<dyn UpstreamConnection>>>,
}

pub(super) struct BoundServer {
    pub(super) index: usize,
    pub(super) connection: Arc<dyn UpstreamConnection>,
}

#[derive(Default)]
struct ClientTracker {
    active_clients: AtomicUsize,
    drained: Notify,
}

struct ClientGuard {
    tracker: Arc<ClientTracker>,
}

impl ClientTracker {
    fn start_guard(self: &Arc<Self>) -> ClientGuard {
        self.active_clients.fetch_add(1, Ordering::Relaxed);
        ClientGuard {
            tracker: Arc::clone(self),
        }
    }

    async fn wait_for_zero(&self) {
        loop {
            let notified = self.drained.notified();
            if self.active_clients.load(Ordering::Relaxed) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        if self.tracker.active_clients.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.tracker.drained.notify_waiters();
        }
    }
}

impl ServiceState {
    pub(super) fn new(
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
            active_index: RwLock::new(0),
            preferred_probe_interval,
            client_tracker: Arc::new(ClientTracker::default()),
        }
    }

    pub(super) async fn warm_connections(&self) {
        for index in 0..self.servers.len() {
            if let Err(error) = self.ensure_connection(index).await {
                log::warn!(
                    "Initial connection attempt to {} failed: {error}",
                    self.servers[index].address
                );
            }
        }
    }

    pub(super) fn server_count(&self) -> usize {
        self.servers.len()
    }

    pub(super) fn spawn_preferred_probe(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(state.preferred_probe_interval).await;

                if state.servers.len() <= 1 {
                    continue;
                }

                let active_index = *state.active_index.read().await;
                if active_index == 0 {
                    continue;
                }

                match state.ensure_connection(0).await {
                    Ok(connection) if connection.is_usable_for_new_sessions().await => {
                        log::info!(
                            "Preferred TACACS+ server {} recovered; routing new sessions back to it",
                            connection.server_address()
                        );
                        *state.active_index.write().await = 0;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        log::debug!("Preferred TACACS+ server probe failed: {error}");
                    }
                }
            }
        })
    }

    pub(super) async fn handle_client<S>(&self, mut stream: S) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _client_guard = self.client_tracker.start_guard();
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

    pub(super) async fn bind_server_for_new_session(&self) -> anyhow::Result<BoundServer> {
        let start_index = *self.active_index.read().await;

        for offset in 0..self.servers.len() {
            let index = (start_index + offset) % self.servers.len();
            match self.ensure_connection(index).await {
                Ok(connection) if connection.is_usable_for_new_sessions().await => {
                    *self.active_index.write().await = index;
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
        let mut active_index = self.active_index.write().await;
        if *active_index == index {
            *active_index = (index + 1) % self.servers.len();
        }
    }

    pub(super) async fn wait_for_active_clients(&self) {
        self.client_tracker.wait_for_zero().await;
    }
}
