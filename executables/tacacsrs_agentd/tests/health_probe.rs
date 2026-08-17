use std::net::SocketAddr;
use std::process::Output;

use tacacsrs_agent_client::health::{HealthClient, READINESS_HEALTH_SERVICE};
use tacacsrs_agent_client::IpcEndpoint;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::Code;
use tonic_health::ServingStatus;

const EXIT_NOT_SERVING: i32 = 1;
const EXIT_CHECK_ERROR: i32 = 3;

async fn run_probe(endpoint: &str, check: &str, timeout_seconds: u64) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tacacsrs-agent-health"))
        .args([
            "--endpoint",
            endpoint,
            "--check",
            check,
            "--timeout-seconds",
            &timeout_seconds.to_string(),
        ])
        .output()
        .await
        .expect("probe must run")
}

async fn start_tcp_health(
    status: ServingStatus,
) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("health listener must bind");
    let address = listener.local_addr().expect("listener address");
    let incoming = TcpListenerStream::new(listener);
    let (reporter, service) = tonic_health::server::health_reporter();
    reporter
        .set_service_status(READINESS_HEALTH_SERVICE, status)
        .await;
    let cancellation = CancellationToken::new();
    let child = cancellation.clone();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, child.cancelled_owned())
            .await
            .expect("health server must run");
    });
    (address, cancellation, task)
}

#[tokio::test]
async fn tcp_probe_exit_codes_are_stable() {
    let (address, cancellation, task) = start_tcp_health(ServingStatus::Serving).await;
    let endpoint = address.to_string();

    let serving = run_probe(&endpoint, "readiness", 2).await;
    assert!(serving.status.success());

    cancellation.cancel();
    task.await.expect("server task must join");
    let unavailable = run_probe(&endpoint, "readiness", 2).await;
    assert_eq!(unavailable.status.code(), Some(EXIT_CHECK_ERROR));
    let diagnostic = String::from_utf8_lossy(&unavailable.stderr);
    for forbidden in [
        "redis://",
        "192.0.2.10",
        "credential-reference",
        "test-secret",
    ] {
        assert!(!diagnostic.contains(forbidden), "probe output exposed {forbidden}");
    }
}

#[tokio::test]
async fn not_serving_and_unknown_service_are_distinct_standard_results() {
    let (address, cancellation, task) = start_tcp_health(ServingStatus::NotServing).await;
    let endpoint = IpcEndpoint::Tcp(address);

    let not_serving = run_probe(&address.to_string(), "readiness", 2).await;
    assert_eq!(not_serving.status.code(), Some(EXIT_NOT_SERVING));

    let mut client = HealthClient::connect(&endpoint)
        .await
        .expect("health client must connect");
    let error = client
        .check("tacacsrs.agent.health.v1.Unknown")
        .await
        .expect_err("unknown service must fail");
    assert_eq!(error.code(), Code::NotFound);

    cancellation.cancel();
    task.await.expect("server task must join");
}

#[tokio::test]
async fn timeout_returns_check_error() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("silent listener must bind");
    let endpoint = listener.local_addr().expect("listener address").to_string();
    let connection = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("probe must connect");
        std::future::pending::<()>().await;
    });

    let output = run_probe(&endpoint, "liveness", 1).await;

    connection.abort();
    assert_eq!(output.status.code(), Some(EXIT_CHECK_ERROR));
    assert!(String::from_utf8_lossy(&output.stderr).contains("timed out"));
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_probe_reports_serving() {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be valid")
        .as_nanos();
    let path = PathBuf::from(format!("/tmp/tacacsrs-health-probe-{unique}.sock"));
    let listener = UnixListener::bind(&path).expect("health socket must bind");
    let incoming = UnixListenerStream::new(listener);
    let (reporter, service) = tonic_health::server::health_reporter();
    reporter
        .set_service_status(READINESS_HEALTH_SERVICE, ServingStatus::Serving)
        .await;
    let cancellation = CancellationToken::new();
    let child = cancellation.clone();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, child.cancelled_owned())
            .await
            .expect("health server must run");
    });

    let output = run_probe(path.to_str().expect("UTF-8 path"), "readiness", 2).await;

    cancellation.cancel();
    task.await.expect("server task must join");
    tokio::fs::remove_file(path)
        .await
        .expect("remove health socket");
    assert!(output.status.success());
}
