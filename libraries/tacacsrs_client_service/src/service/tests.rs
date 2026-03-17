use std::collections::HashMap;
#[cfg(not(unix))]
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;

use super::config::{IpcEndpoint, ServiceConfig};
use super::coordinator::TacacsClientService;
use super::state::ServiceState;
use crate::client::ServiceClient;
use crate::protocol::{AccountingOperation, AccountingOperationResponse, AccountingResponseStatus};
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
        upstream: UpstreamConnectionOptions::default(),
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

    let connector = Arc::new(FakeConnector {
        connections: HashMap::from([(primary.address.clone(), Arc::clone(&primary))]),
    });

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

    let connector = Arc::new(FakeConnector {
        connections: HashMap::from([(primary.address.clone(), Arc::clone(&primary))]),
    });

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
