use std::collections::HashMap;
#[cfg(not(unix))]
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus, IpcEndpoint,
    ServiceClient,
};
use tokio::sync::{Mutex, Notify};

use super::config::ServiceConfig;
use super::coordinator::TacacsClientService;
use super::state::ServiceState;
use crate::upstream::{UpstreamConnection, UpstreamConnectionOptions, UpstreamConnector};

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
        _request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        if self.fail_next_request.swap(false, Ordering::Relaxed) {
            self.usable.store(false, Ordering::Relaxed);
            anyhow::bail!("simulated failure from {}", self.address);
        }

        Ok(AccountingOperationResponse {
            server: self.address.clone(),
            status: AccountingResponseStatus::Success,
            server_message: format!("handled by {}", self.address),
            data: String::new(),
        })
    }
}

#[derive(Debug)]
struct FakeConnector {
    connections: HashMap<String, Arc<FakeConnection>>,
    connect_attempts: Mutex<HashMap<String, usize>>,
    connect_delay: Duration,
    in_flight_connects: AtomicUsize,
    max_in_flight_connects: AtomicUsize,
}

#[derive(Debug)]
struct SingleSessionConnection {
    address: String,
    usable: AtomicBool,
}

#[async_trait]
impl UpstreamConnection for SingleSessionConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn is_usable_for_new_sessions(&self) -> bool {
        self.usable.load(Ordering::Relaxed)
    }

    async fn send_accounting(
        &self,
        _request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        self.usable.store(false, Ordering::Relaxed);
        Ok(AccountingOperationResponse {
            server: self.address.clone(),
            status: AccountingResponseStatus::Success,
            server_message: "single-session upstream".to_owned(),
            data: String::new(),
        })
    }
}

#[derive(Debug)]
struct SingleSessionConnector {
    address: String,
    connect_attempts: AtomicUsize,
}

#[async_trait]
impl UpstreamConnector for SingleSessionConnector {
    async fn connect(&self, address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        assert_eq!(address, self.address);
        self.connect_attempts.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(SingleSessionConnection {
            address: self.address.clone(),
            usable: AtomicBool::new(true),
        }))
    }
}

impl FakeConnector {
    fn new(connections: HashMap<String, Arc<FakeConnection>>) -> Self {
        Self {
            connections,
            connect_attempts: Mutex::new(HashMap::new()),
            connect_delay: Duration::ZERO,
            in_flight_connects: AtomicUsize::new(0),
            max_in_flight_connects: AtomicUsize::new(0),
        }
    }

    fn with_connect_delay(mut self, connect_delay: Duration) -> Self {
        self.connect_delay = connect_delay;
        self
    }

    async fn connect_attempts_for(&self, address: &str) -> usize {
        *self
            .connect_attempts
            .lock()
            .await
            .get(address)
            .unwrap_or(&0)
    }

    fn max_in_flight_connects(&self) -> usize {
        self.max_in_flight_connects.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl UpstreamConnector for FakeConnector {
    async fn connect(&self, address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        {
            let mut attempts = self.connect_attempts.lock().await;
            *attempts.entry(address.to_owned()).or_default() += 1;
        }

        let in_flight = self.in_flight_connects.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_in_flight_connects
            .fetch_max(in_flight, Ordering::Relaxed);
        if !self.connect_delay.is_zero() {
            tokio::time::sleep(self.connect_delay).await;
        }

        let connection = self
            .connections
            .get(address)
            .with_context(|| format!("missing fake connection for {address}"))?;

        let result = if connection.usable.load(Ordering::Relaxed) {
            Ok(Arc::clone(connection) as Arc<dyn UpstreamConnection>)
        } else {
            Err(anyhow::anyhow!("{address} is currently down"))
        };

        self.in_flight_connects.fetch_sub(1, Ordering::Relaxed);
        result
    }
}

fn build_request() -> AccountingOperation {
    AccountingOperation {
        user: "admin".to_owned(),
        port: "tty0".to_owned(),
        remote_address: "127.0.0.1".to_owned(),
        command: "show".to_owned(),
        command_arguments: vec!["users".to_owned()],
    }
}

fn service_config(endpoint: IpcEndpoint, server_addresses: Vec<String>) -> ServiceConfig {
    ServiceConfig {
        endpoint,
        server_addresses,
        upstream: UpstreamConnectionOptions {
            connect_timeout: Duration::from_millis(50),
            ..UpstreamConnectionOptions::default()
        },
        preferred_probe_interval: Duration::from_millis(50),
        #[cfg(unix)]
        socket_mode: 0o660,
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
        let _ = socket_name;
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

    let connector = Arc::new(FakeConnector::new(HashMap::from([
        (first.address.clone(), Arc::clone(&first)),
        (second.address.clone(), Arc::clone(&second)),
        (third.address.clone(), Arc::clone(&third)),
    ])));

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

    let connector = Arc::new(FakeConnector::new(HashMap::from([
        (primary.address.clone(), Arc::clone(&primary)),
        (secondary.address.clone(), Arc::clone(&secondary)),
    ])));

    let endpoint = test_endpoint("tacacs-service-test");
    let config =
        service_config(endpoint.clone(), vec![primary.address.clone(), secondary.address.clone()]);

    let service = TacacsClientService::new_with_connector(config, connector).unwrap();
    let service_task = tokio::spawn(async move { service.serve().await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = ServiceClient::new(endpoint.clone());
    let request = build_request();

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

#[cfg(unix)]
#[tokio::test]
async fn test_existing_socket_path_is_not_unlinked() {
    let primary = Arc::new(FakeConnection {
        address: "primary:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });

    let connector = Arc::new(FakeConnector::new(HashMap::from([(
        primary.address.clone(),
        Arc::clone(&primary),
    )])));

    let endpoint = test_endpoint("tacacs-service-existing-socket");
    let path = match &endpoint {
        IpcEndpoint::Unix(path) => path.clone(),
        IpcEndpoint::Tcp(_) => unreachable!(),
    };

    let existing_listener = tokio::net::UnixListener::bind(&path).unwrap();
    let config = service_config(endpoint, vec![primary.address.clone()]);

    let service = TacacsClientService::new_with_connector(config, connector).unwrap();
    let error = service.serve().await.unwrap_err();
    assert!(error.to_string().contains("already accepting connections"));

    drop(existing_listener);
    let _ = tokio::fs::remove_file(path).await;
}

#[cfg(unix)]
#[tokio::test]
async fn test_stale_socket_path_is_replaced() {
    let primary = Arc::new(FakeConnection {
        address: "primary:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });

    let connector = Arc::new(FakeConnector::new(HashMap::from([(
        primary.address.clone(),
        Arc::clone(&primary),
    )])));

    let endpoint = test_endpoint("tacacs-service-stale-socket");
    let path = match &endpoint {
        IpcEndpoint::Unix(path) => path.clone(),
        IpcEndpoint::Tcp(_) => unreachable!(),
    };

    let stale_listener = tokio::net::UnixListener::bind(&path).unwrap();
    drop(stale_listener);

    let config = service_config(endpoint, vec![primary.address.clone()]);

    let service = TacacsClientService::new_with_connector(config, connector).unwrap();
    let listener = service.prepare_unix_listener(&path).await.unwrap();
    drop(listener);

    assert!(tokio::fs::try_exists(&path).await.unwrap());
    let _ = tokio::fs::remove_file(path).await;
}

#[tokio::test]
async fn test_warm_connections_stops_after_first_responsive_server() {
    let first = Arc::new(FakeConnection {
        address: "server-a:49".to_owned(),
        usable: AtomicBool::new(false),
        fail_next_request: AtomicBool::new(false),
    });
    let second = Arc::new(FakeConnection {
        address: "server-b:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });
    let third = Arc::new(FakeConnection {
        address: "server-c:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });

    let connector = Arc::new(FakeConnector::new(HashMap::from([
        (first.address.clone(), Arc::clone(&first)),
        (second.address.clone(), Arc::clone(&second)),
        (third.address.clone(), Arc::clone(&third)),
    ])));

    let state = ServiceState::new(
        vec![
            first.address.clone(),
            second.address.clone(),
            third.address.clone(),
        ],
        Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
        Duration::from_millis(25),
    );

    state.warm_connections().await;

    assert_eq!(connector.connect_attempts_for(&first.address).await, 1);
    assert_eq!(connector.connect_attempts_for(&second.address).await, 1);
    assert_eq!(connector.connect_attempts_for(&third.address).await, 0);

    let bound = state.bind_server_for_new_session().await.unwrap();
    assert_eq!(bound.connection.server_address(), second.address);
    assert_eq!(connector.connect_attempts_for(&second.address).await, 1);
}

#[tokio::test]
async fn test_concurrent_failover_coalesces_connection_attempts() {
    let first = Arc::new(FakeConnection {
        address: "server-a:49".to_owned(),
        usable: AtomicBool::new(false),
        fail_next_request: AtomicBool::new(false),
    });
    let second = Arc::new(FakeConnection {
        address: "server-b:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });

    let connector = Arc::new(
        FakeConnector::new(HashMap::from([
            (first.address.clone(), Arc::clone(&first)),
            (second.address.clone(), Arc::clone(&second)),
        ]))
        .with_connect_delay(Duration::from_millis(25)),
    );

    let state = Arc::new(ServiceState::new(
        vec![first.address.clone(), second.address.clone()],
        Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
        Duration::from_millis(200),
    ));

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            let bound = state.bind_server_for_new_session().await.unwrap();
            bound.connection.server_address().to_owned()
        }));
    }

    for task in tasks {
        assert_eq!(task.await.unwrap(), second.address);
    }

    assert_eq!(connector.connect_attempts_for(&first.address).await, 1);
    assert_eq!(connector.connect_attempts_for(&second.address).await, 1);
    assert_eq!(connector.max_in_flight_connects(), 1);
}

#[tokio::test]
async fn test_non_single_connection_is_reconnected_for_next_request() {
    let connector = Arc::new(SingleSessionConnector {
        address: "server-a:49".to_owned(),
        connect_attempts: AtomicUsize::new(0),
    });

    let state = ServiceState::new(
        vec![connector.address.clone()],
        Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
        Duration::from_millis(200),
    );

    let first = state.bind_server_for_new_session().await.unwrap();
    first
        .connection
        .send_accounting(&build_request())
        .await
        .unwrap();

    let second = state.bind_server_for_new_session().await.unwrap();
    assert_eq!(second.connection.server_address(), connector.address);
    assert_eq!(connector.connect_attempts.load(Ordering::Relaxed), 2);
}

// ---------------------------------------------------------------------------
// ClientTracker / drain-wait tests
// ---------------------------------------------------------------------------

/// Connection whose `send_accounting` blocks until an external signal fires.
/// This lets tests hold the client guard alive for a controlled duration.
#[derive(Debug)]
struct BlockingConnection {
    address: String,
    release: Arc<Notify>,
}

#[async_trait]
impl UpstreamConnection for BlockingConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn is_usable_for_new_sessions(&self) -> bool {
        true
    }

    async fn send_accounting(
        &self,
        _request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        self.release.notified().await;
        Ok(AccountingOperationResponse {
            server: self.address.clone(),
            status: AccountingResponseStatus::Success,
            server_message: String::new(),
            data: String::new(),
        })
    }
}

#[derive(Debug)]
struct BlockingConnector {
    connection: Arc<BlockingConnection>,
}

#[async_trait]
impl UpstreamConnector for BlockingConnector {
    async fn connect(&self, _address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        Ok(Arc::clone(&self.connection) as Arc<dyn UpstreamConnection>)
    }
}

#[tokio::test]
async fn test_drain_returns_immediately_with_no_active_clients() {
    let release = Arc::new(Notify::new());
    let connector = Arc::new(BlockingConnector {
        connection: Arc::new(BlockingConnection {
            address: "server:49".to_owned(),
            release,
        }),
    });
    let state = ServiceState::new(
        vec!["server:49".to_owned()],
        connector,
        Duration::from_secs(60),
    );

    // No requests in flight — drain should return immediately.
    tokio::time::timeout(Duration::from_millis(100), state.wait_for_active_clients())
        .await
        .expect("wait_for_active_clients should return immediately with no active clients");
}

#[tokio::test]
async fn test_drain_waits_for_in_flight_request_then_completes() {
    let release = Arc::new(Notify::new());
    let connector = Arc::new(BlockingConnector {
        connection: Arc::new(BlockingConnection {
            address: "server:49".to_owned(),
            release: Arc::clone(&release),
        }),
    });
    let state = Arc::new(ServiceState::new(
        vec!["server:49".to_owned()],
        connector,
        Duration::from_secs(60),
    ));
    state.warm_connections().await;

    // Spawn an in-flight request that blocks inside send_accounting.
    let state_bg = Arc::clone(&state);
    let request_handle = tokio::spawn(async move {
        state_bg
            .execute_accounting_request(build_request())
            .await
            .unwrap();
    });

    // Give the spawned task time to enter send_accounting and acquire the guard.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain should NOT complete while the request is in flight.
    let drain_result =
        tokio::time::timeout(Duration::from_millis(100), state.wait_for_active_clients()).await;
    assert!(
        drain_result.is_err(),
        "wait_for_active_clients should block while a request is in flight"
    );

    // Release the blocked request so the guard drops.
    release.notify_waiters();
    request_handle.await.unwrap();

    // Now drain should complete promptly.
    tokio::time::timeout(Duration::from_millis(100), state.wait_for_active_clients())
        .await
        .expect("wait_for_active_clients should complete after all requests finish");
}

#[tokio::test]
async fn test_drain_completes_when_guard_drops_between_check_and_await() {
    // Regression test for the lost-wakeup race: the guard drops (and
    // notifies) in the window between the load-check and the notified().await
    // inside wait_for_zero. The fix ensures the Notify future is registered
    // before the recheck so no wakeup is lost.
    let release = Arc::new(Notify::new());
    let connector = Arc::new(BlockingConnector {
        connection: Arc::new(BlockingConnection {
            address: "server:49".to_owned(),
            release: Arc::clone(&release),
        }),
    });
    let state = Arc::new(ServiceState::new(
        vec!["server:49".to_owned()],
        connector,
        Duration::from_secs(60),
    ));
    state.warm_connections().await;

    // Spawn a request then release it almost immediately so the guard drop
    // races with the drain waiter.
    let state_bg = Arc::clone(&state);
    let request_handle = tokio::spawn(async move {
        state_bg
            .execute_accounting_request(build_request())
            .await
            .unwrap();
    });

    // Yield briefly to let the task start.
    tokio::task::yield_now().await;

    // Release the request immediately — the guard will drop while the drain
    // waiter is still setting up, exercising the race window.
    release.notify_waiters();
    request_handle.await.unwrap();

    // Drain must still complete; a lost wakeup would cause this to hang.
    tokio::time::timeout(Duration::from_millis(200), state.wait_for_active_clients())
        .await
        .expect("wait_for_active_clients must not hang after a racing guard drop");
}
