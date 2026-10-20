use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, oneshot};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::transport::Server;
use tonic::transport::server::Connected;

use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
use tacacsrs_ipc::proto::tacacs_agent_server::TacacsAgentServer;

use super::{ACCOUNTING_POLICY, accounting_request, state_from};
use crate::controller::tacacs_agent_mock_controller_server::TacacsAgentMockControllerServer;
use crate::service::{AgentService, ControllerService, shutdown_signal};
use crate::{EmulatorPolicy, IpcEmulator, MockControllerClient};

async fn exercise_channels<S, IO>(incoming: S, endpoint: IpcEndpoint)
where
    S: tokio_stream::Stream<Item = Result<IO, std::io::Error>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
{
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let incoming = incoming.map(move |stream| {
        if stream.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
        stream
    });
    let state = Arc::new(Mutex::new(state_from(ACCOUNTING_POLICY)));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(TacacsAgentServer::new(AgentService {
                state: Arc::clone(&state),
            }))
            .add_service(TacacsAgentMockControllerServer::new(ControllerService {
                state,
                shutdown_sender: Arc::new(Mutex::new(Some(shutdown_tx))),
            }))
            .serve_with_incoming_shutdown(incoming, shutdown_signal(shutdown_rx))
            .await
            .expect("counted server must stop cleanly");
    });

    let client = ServiceClient::connect(endpoint.clone())
        .await
        .expect("service client must connect");
    let mut controller = MockControllerClient::connect(endpoint)
        .await
        .expect("controller must connect");
    for _ in 0..3 {
        client
            .clone()
            .send_accounting(accounting_request("admin", "show"))
            .await
            .expect("request must succeed through the reusable channel");
        assert_eq!(controller.captured_requests().await.unwrap().len(), 1);
        controller.reset_state().await.unwrap();
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    controller.shutdown().await.unwrap();
    drop(controller);
    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_clients_reuse_channels() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    assert_ne!(address.port(), 0);
    exercise_channels(TcpListenerStream::new(listener), IpcEndpoint::Tcp(address)).await;
}

#[tokio::test]
async fn unix_clients_reuse_channels() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let path = directory.path().join("emulator.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    exercise_channels(UnixListenerStream::new(listener), IpcEndpoint::Unix(path)).await;
}

#[tokio::test]
async fn connection_errors_identify_both_endpoint_types() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let path = directory.path().join("missing.sock");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    for (endpoint, description) in [
        (IpcEndpoint::Unix(path.clone()), path.display().to_string()),
        (IpcEndpoint::Tcp(address), address.to_string()),
    ] {
        let service_error = ServiceClient::connect(endpoint.clone()).await.unwrap_err();
        let controller_error = MockControllerClient::connect(endpoint).await.err().unwrap();
        assert!(service_error.to_string().contains(&description));
        assert!(controller_error.to_string().contains(&description));
    }
}

#[tokio::test]
async fn emulator_binds_unix_endpoint_for_both_clients() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let path = directory.path().join("emulator.sock");
    let expected = IpcEndpoint::Unix(path.clone());
    let (emulator, endpoint) = IpcEmulator::from_policy_at_endpoint(
        EmulatorPolicy::new(ACCOUNTING_POLICY),
        expected.clone(),
    )
    .await
    .unwrap();
    assert_eq!(endpoint, expected);
    let client = ServiceClient::connect(endpoint.clone()).await.unwrap();
    let mut controller = MockControllerClient::connect(endpoint).await.unwrap();
    client
        .send_accounting(accounting_request("admin", "show"))
        .await
        .unwrap();
    assert_eq!(controller.captured_requests().await.unwrap().len(), 1);
    drop(client);
    drop(controller);
    emulator.shutdown().await;
    assert!(!path.exists());
}

#[tokio::test]
async fn emulator_reports_ephemeral_tcp_endpoint() {
    let (emulator, endpoint) = IpcEmulator::from_policy(EmulatorPolicy::new(ACCOUNTING_POLICY))
        .await
        .unwrap();
    let IpcEndpoint::Tcp(address) = endpoint else {
        panic!("the default emulator endpoint must use TCP");
    };
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    let client = ServiceClient::connect(IpcEndpoint::Tcp(address))
        .await
        .unwrap();
    let mut controller = MockControllerClient::connect(IpcEndpoint::Tcp(address))
        .await
        .unwrap();
    client
        .send_accounting(accounting_request("admin", "show"))
        .await
        .unwrap();
    assert_eq!(controller.captured_requests().await.unwrap().len(), 1);
    drop(client);
    drop(controller);
    emulator.shutdown().await;
}
