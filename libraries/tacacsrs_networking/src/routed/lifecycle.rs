//! Endpoint setup ownership and deadline-bound retirement across catalogs.

use std::sync::{Arc, Mutex};

use anyhow::{Context, ensure};
use tokio::sync::oneshot;

use crate::{PreparedEndpoint, RequestDeadline};
use crate::connection::task::DriverTask;

use super::{Endpoint, EndpointConnector, OperationKind};

/// Maximum graceful retirement wait before forcing connector cleanup.
const FAILURE_RETIREMENT_BUDGET: std::time::Duration = std::time::Duration::from_secs(1);

struct State<Connection: ?Sized> {
    closed: bool,
    cutoff: Option<RequestDeadline>,
    connections: Vec<Arc<Connection>>,
    setups: Vec<Arc<DriverTask>>,
    cleanups: Vec<Arc<DriverTask>>,
    runtime: Option<tokio::runtime::Handle>,
    retirement: Option<Arc<DriverTask>>,
}

pub(super) struct EndpointLifecycle<Connector: EndpointConnector> {
    pub(super) endpoint_name: String,
    endpoint_identity: Option<Arc<()>>,
    connector: Arc<Connector>,
    state: Mutex<State<Connector::Connection>>,
    _payload: crate::PreparationPayload,
}

struct SetupGuard(Arc<DriverTask>);

pub(super) struct PendingConnection<Connector: EndpointConnector> {
    owner: Arc<EndpointLifecycle<Connector>>,
    connection: Arc<Connector::Connection>,
    adopted: bool,
}

impl<Connector: EndpointConnector> PendingConnection<Connector> {
    pub(super) fn adopt(mut self) -> Arc<Connector::Connection> {
        self.adopted = true;
        self.connection.clone()
    }
}

impl<Connector: EndpointConnector> Drop for PendingConnection<Connector> {
    fn drop(&mut self) {
        if !self.adopted {
            self.owner.abandon(self.connection.clone());
        }
    }
}

impl Drop for SetupGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<Connector: EndpointConnector> EndpointLifecycle<Connector> {
    pub(super) fn new(connector: Arc<Connector>, endpoint_name: &str) -> Self {
        Self {
            endpoint_name: endpoint_name.to_owned(),
            endpoint_identity: None,
            connector,
            state: Mutex::new(State {
                closed: false,
                cutoff: None,
                connections: Vec::new(),
                setups: Vec::new(),
                cleanups: Vec::new(),
                runtime: None,
                retirement: None,
            }),
            _payload: crate::PreparationPayload::default(),
        }
    }

    pub(super) fn for_endpoint(connector: Arc<Connector>, endpoint: &Endpoint) -> Self {
        let mut lifecycle = Self::new(connector, endpoint.name());
        lifecycle.endpoint_identity = Some(endpoint.identity());
        lifecycle._payload = endpoint.prepared().preparation_payload.clone();
        lifecycle
    }

    pub(super) fn ensure_open(&self) -> anyhow::Result<()> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure!(
            !state.closed && state.cutoff.is_none_or(|deadline| deadline.check().is_ok()),
            "The TACACS+ endpoint is retired"
        );
        Ok(())
    }

    pub(super) async fn connect(
        self: &Arc<Self>,
        endpoint: PreparedEndpoint,
        operation: OperationKind,
    ) -> anyhow::Result<PendingConnection<Connector>> {
        self.reap_unused_connections().await;
        let (sender, receiver) = oneshot::channel();
        let task = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure!(
                !state.closed && state.cutoff.is_none_or(|deadline| deadline.check().is_ok()),
                "The TACACS+ endpoint is retired"
            );
            state.setups.retain(|task| !task.is_finished());
            state.runtime = Some(tokio::runtime::Handle::current());
            let owner = Arc::downgrade(self);
            let connector = Arc::clone(&self.connector);
            let task = Arc::new(DriverTask::spawn(async move {
                let result = connector
                    .connect(endpoint, operation)
                    .await
                    .and_then(|connection| {
                        let Some(owner) = owner.upgrade() else {
                            connector.close(&connection);
                            anyhow::bail!("The TACACS+ endpoint owner was dropped");
                        };
                        let mut state = owner
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.connections.push(connection.clone());
                        drop(state);
                        let pending = PendingConnection {
                            owner,
                            connection,
                            adopted: false,
                        };
                        pending.owner.ensure_open()?;
                        Ok(pending)
                    });
                let _delivered = sender.send(result);
                Ok(())
            }));
            state.setups.push(task.clone());
            task
        };
        let _setup = SetupGuard(task);
        let connection = receiver
            .await
            .context("TACACS+ endpoint setup was cancelled")??;
        self.ensure_open()?;
        Ok(connection)
    }

    fn abandon(self: &Arc<Self>, connection: Arc<Connector::Connection>) {
        self.connector.close(&connection);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed
            || !state
                .connections
                .iter()
                .any(|current| Arc::ptr_eq(current, &connection))
        {
            return;
        }
        state.cleanups.retain(|task| !task.is_finished());
        let Some(runtime) = state.runtime.clone() else {
            return;
        };
        let owner = Arc::downgrade(self);
        let connector = self.connector.clone();
        state
            .cleanups
            .push(Arc::new(DriverTask::spawn_on(&runtime, async move {
                let result = connector
                    .close_and_join(&connection, RequestDeadline::at(tokio::time::Instant::now()))
                    .await;
                if let Some(owner) = owner.upgrade() {
                    owner
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .connections
                        .retain(|current| !Arc::ptr_eq(current, &connection));
                }
                result
            })));
    }

    pub(super) fn retire_failed(&self, connection: Arc<Connector::Connection>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return;
        }
        state.cleanups.retain(|task| !task.is_finished());
        let Some(runtime) = state.runtime.clone() else {
            return;
        };
        let connector = self.connector.clone();
        state
            .cleanups
            .push(Arc::new(DriverTask::spawn_on(&runtime, async move {
                if tokio::time::timeout(FAILURE_RETIREMENT_BUDGET, connector.retire(&connection))
                    .await
                    .is_err()
                {
                    connector
                        .close_and_join(
                            &connection,
                            RequestDeadline::at(tokio::time::Instant::now()),
                        )
                        .await?;
                }
                Ok(())
            })));
    }

    async fn reap_unused_connections(&self) {
        let unused = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connections
            .iter()
            .filter(|connection| Arc::strong_count(connection) == 1)
            .cloned()
            .collect::<Vec<_>>();
        for connection in unused {
            self.connector.close(&connection);
            if let Err(error) = self
                .connector
                .close_and_join(&connection, RequestDeadline::at(tokio::time::Instant::now()))
                .await
            {
                log::debug!("Retired connection cleanup reported: {error:#}");
            }
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .connections
                .retain(|current| !Arc::ptr_eq(current, &connection));
        }
    }

    pub(super) fn close(&self) {
        let connections = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.closed = true;
            for setup in &state.setups {
                setup.abort();
            }
            state.connections.clone()
        };
        for connection in connections {
            self.connector.close(&connection);
        }
    }

    async fn join_connections(&self, deadline: RequestDeadline) -> anyhow::Result<()> {
        self.close();
        let setups = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.setups.clone()
        };
        let mut failure = None;
        for task in setups {
            if let Err(error) = task.join_until(deadline).await {
                failure.get_or_insert(error);
            }
        }
        let (cleanups, connections) = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (state.cleanups.clone(), state.connections.clone())
        };
        for task in cleanups {
            if let Err(error) = task.join_until(deadline).await {
                failure.get_or_insert(error);
            }
        }
        for connection in connections {
            if let Err(error) = self.connector.close_and_join(&connection, deadline).await {
                failure.get_or_insert(error);
            }
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.connections.clear();
        state.setups.retain(|task| !task.is_finished());
        state.cleanups.retain(|task| !task.is_finished());
        failure.map_or(Ok(()), Err)
    }

    pub(super) fn retire(self: &Arc<Self>, deadline: RequestDeadline) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .cutoff
            .is_some_and(|current| current.expires_at() <= deadline.expires_at())
        {
            return;
        }
        if let Some(previous) = state.retirement.take() {
            previous.abort();
        }
        state.cutoff = Some(deadline);
        let owner = Arc::downgrade(self);
        state.retirement = Some(Arc::new(DriverTask::spawn(async move {
            tokio::time::sleep_until(deadline.expires_at()).await;
            if let Some(owner) = owner.upgrade() {
                owner.join_connections(deadline).await?;
            }
            Ok(())
        })));
    }

    pub(super) async fn close_and_join(&self, deadline: RequestDeadline) -> anyhow::Result<()> {
        let result = self.join_connections(deadline).await;
        let retirement = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retirement
            .clone();
        if let Some(task) = retirement {
            task.abort();
            let joined = task.join_until(deadline).await;
            return result.and(joined);
        }
        result
    }

    fn is_unused(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.cutoff.is_none()
            && state.connections.is_empty()
            && state.setups.iter().all(|task| task.is_finished())
            && state.cleanups.iter().all(|task| task.is_finished())
    }

    fn is_retiring(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.cutoff.is_some() && !state.closed
    }

    fn finished(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed
            && state
                .retirement
                .as_ref()
                .is_some_and(|task| task.is_finished())
    }
}

impl<Connector: EndpointConnector> Drop for EndpointLifecycle<Connector> {
    fn drop(&mut self) {
        self.close();
    }
}

pub(super) struct RoutingRuntime<Connector: EndpointConnector> {
    state: Mutex<(bool, Vec<Arc<EndpointLifecycle<Connector>>>)>,
}

impl<Connector: EndpointConnector> Default for RoutingRuntime<Connector> {
    fn default() -> Self {
        Self {
            state: Mutex::new((false, Vec::new())),
        }
    }
}

impl<Connector: EndpointConnector> RoutingRuntime<Connector> {
    pub(super) fn discard_idle(&self, endpoint: &Arc<EndpointLifecycle<Connector>>) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
            .retain(|lifecycle| !Arc::ptr_eq(endpoint, lifecycle) || !lifecycle.is_unused());
    }

    pub(super) fn retains_endpoint(&self, endpoint: &Endpoint) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
            .iter()
            .any(|lifecycle| {
                lifecycle
                    .endpoint_identity
                    .as_ref()
                    .is_some_and(|retained| Arc::ptr_eq(retained, &endpoint.identity()))
                    && !lifecycle.finished()
            })
    }

    pub(super) fn retiring_endpoints(&self) -> Vec<Arc<EndpointLifecycle<Connector>>> {
        let endpoints = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
            .clone();
        endpoints
            .into_iter()
            .filter(|endpoint| endpoint.is_retiring())
            .collect()
    }

    pub(super) fn register(&self, endpoint: Arc<EndpointLifecycle<Connector>>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.1.retain(|endpoint| !endpoint.finished());
        if state.0 {
            endpoint.close();
        }
        state.1.push(endpoint);
    }

    pub(super) fn ensure_open(&self) -> anyhow::Result<()> {
        ensure!(
            !self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0,
            "The routed TACACS+ client is closed"
        );
        Ok(())
    }

    pub(super) fn close(&self) {
        let endpoints = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.0 = true;
            state.1.clone()
        };
        for endpoint in endpoints {
            endpoint.close();
        }
    }

    pub(super) fn cancel(&self) {
        self.close();
        let endpoints = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
            .clone();
        for endpoint in endpoints {
            endpoint.retire(RequestDeadline::at(tokio::time::Instant::now()));
        }
    }

    pub(super) async fn close_and_join(&self, deadline: RequestDeadline) -> anyhow::Result<()> {
        self.close();
        let endpoints = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
            .clone();
        let mut failure = None;
        for endpoint in endpoints {
            if let Err(error) = endpoint.close_and_join(deadline).await {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::ConnectOptions;

    #[derive(Default)]
    struct CleanupConnector {
        joined: AtomicUsize,
    }

    #[async_trait]
    impl EndpointConnector for CleanupConnector {
        type Connection = ();

        async fn connect(&self, _: PreparedEndpoint, _: OperationKind) -> anyhow::Result<Arc<()>> {
            Ok(Arc::new(()))
        }

        async fn retire(&self, (): &()) {}

        fn close(&self, (): &()) {}

        async fn close_and_join(&self, (): &(), _: RequestDeadline) -> anyhow::Result<()> {
            self.joined.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn unclaimed_successful_setup_is_cleaned_without_another_bind() {
        let connector = Arc::new(CleanupConnector::default());
        let lifecycle = Arc::new(EndpointLifecycle::new(connector.clone(), "test"));
        let endpoint = PreparedEndpoint::new(
            crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
            crate::PreparedTransport::Tcp,
            false,
            None,
            ConnectOptions::default(),
        );
        let mut pending = Box::pin(lifecycle.connect(endpoint, OperationKind::Accounting));
        std::future::poll_fn(|context| {
            assert!(pending.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let task = lifecycle.state.lock().unwrap().setups[0].clone();
        task.join_until(RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        assert_eq!(lifecycle.state.lock().unwrap().connections.len(), 1);
        drop(pending);
        tokio::time::timeout(Duration::from_secs(1), async {
            while connector.joined.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unclaimed connection cleanup must finish independently");
        assert!(lifecycle.state.lock().unwrap().connections.is_empty());
    }

    #[test]
    fn pending_connection_can_be_dropped_outside_runtime_context() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let connector = Arc::new(CleanupConnector::default());
        let lifecycle = Arc::new(EndpointLifecycle::new(connector.clone(), "test"));
        let pending = runtime
            .block_on(lifecycle.connect(
                PreparedEndpoint::new(
                    crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::Accounting,
            ))
            .unwrap();
        drop(pending);
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(1), async {
                while connector.joined.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        });
        assert!(lifecycle.state.lock().unwrap().connections.is_empty());
    }

    #[tokio::test]
    async fn unclaimed_watchdog_connection_closes_its_socket_and_owner() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tacacsrs_protocol::accounting::reply::AccountingReply;
        use tacacsrs_protocol::enumerations::{TacacsAccountingStatus, TacacsFlags};
        use tacacsrs_protocol::packet::{Packet, PacketTrait};
        use tacacsrs_protocol::body::TacacsBodyTrait;
        use crate::{ConnectPreflight, PacketReader, PacketReadResult};

        tokio::time::timeout(Duration::from_secs(2), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let lifecycle =
                Arc::new(EndpointLifecycle::new(Arc::new(super::super::NativeConnector), "test"));
            let endpoint = PreparedEndpoint::new(
                listener.local_addr().unwrap().try_into().unwrap(),
                crate::PreparedTransport::Tcp,
                true,
                None,
                ConnectOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog),
            );
            let mut pending = Box::pin(lifecycle.connect(endpoint, OperationKind::Accounting));
            std::future::poll_fn(|context| {
                assert!(pending.as_mut().poll(context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            let (mut peer, _) = listener.accept().await.unwrap();
            let PacketReadResult::Success(request) =
                PacketReader::new(None).read_packet(&mut peer).await
            else {
                panic!("watchdog request expected");
            };
            assert!(request
                .header()
                .flags
                .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
            let body = AccountingReply {
                status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
                server_msg: String::new(),
                data: String::new(),
            }
            .to_bytes()
            .unwrap();
            let mut header = request.header().clone();
            header.seq_no += 1;
            header.length = u32::try_from(body.len()).unwrap();
            peer.write_all(&Packet::new(header, body).unwrap().to_bytes())
                .await
                .unwrap();
            let task = lifecycle.state.lock().unwrap().setups[0].clone();
            task.join_until(RequestDeadline::after(Duration::from_secs(1)).unwrap())
                .await
                .unwrap();
            let connection = Arc::downgrade(&lifecycle.state.lock().unwrap().connections[0]);
            drop(pending);
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            while connection.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
            assert!(lifecycle.state.lock().unwrap().connections.is_empty());
        })
        .await
        .expect("unclaimed promoted connection must be cleaned independently");
    }
}
