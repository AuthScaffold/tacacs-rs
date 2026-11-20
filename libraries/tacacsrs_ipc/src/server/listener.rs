//! Unix domain socket IPC listener over an operation [`Handler`].

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::watch;
use tacacsrs_unix_socket::prepare_unix_listener;

use super::Handler;
use super::grpc::GrpcService;
use super::health::{HealthStatus, StandardHealth};
use super::limited_incoming::LimitedIncoming;
use super::request_tracker::RequestTracker;
use crate::diagnostics::DiagnosticsService;
use crate::health_details::{self, AgentHealthService};
use crate::proto::agent_health_server::AgentHealthServer;
use crate::proto::diagnostics_server::DiagnosticsServer;
use crate::proto::tacacs_agent_server::TacacsAgentServer;
use crate::{DiagnosticsProvider, HealthDetailsProvider};

/// Allows protobuf framing overhead while rejecting multi-megabyte envelopes.
const MAX_IPC_MESSAGE_BYTES: usize =
    2 * tacacsrs_protocol::constants::TACACS_MAX_BODY_LENGTH as usize;

/// Transport-neutral settings for the IPC Unix domain socket listener.
///
/// The host projects canonical configuration into these values. The listener
/// does not read YANG, generated configuration, or agent runtime state.
#[derive(Debug, Clone, Copy)]
pub struct ListenerOptions {
    /// Unix socket file permission bits.
    pub socket_mode: u32,
    /// Maximum number of simultaneously accepted connections.
    pub max_connections: usize,
    /// Maximum number of concurrent HTTP/2 streams per connection.
    pub max_client_api_streams: u32,
    /// Maximum lifetime of one accepted connection.
    pub connection_lifetime: Duration,
}

/// Runs the Unix domain socket IPC listener until shutdown starts.
///
/// The listener binds the socket, publishes standard gRPC health from the
/// neutral `readiness` signal, and serves the generated `TacacsAgent` service
/// backed by `handler`. It calls `on_bound` once after the socket is bound. The
/// `shutdown` signal becomes `true` to stop accepting work; the listener then
/// drains active requests and removes an owned socket path.
///
/// # Errors
/// Returns a bind, serve, or socket-cleanup error after draining.
pub async fn serve_unix<H, B>(
    path: &Path,
    options: ListenerOptions,
    handler: Arc<H>,
    readiness: watch::Receiver<HealthStatus>,
    shutdown: watch::Receiver<bool>,
    on_bound: B,
) -> anyhow::Result<()>
where
    H: Handler,
    B: FnOnce() + Send,
{
    serve_unix_with_services(
        path,
        options,
        handler,
        readiness,
        shutdown,
        on_bound,
        ListenerServices::default(),
    )
    .await
}

/// Optional read-only services that share the listener socket.
///
/// Each provider adds one gRPC route. Without a diagnostics provider, the
/// `Diagnostics` service returns `Unimplemented`. Without a health details
/// provider, the listener does not add the `AgentHealth` route, and gRPC
/// returns `Unimplemented`.
#[derive(Clone, Default)]
pub struct ListenerServices {
    diagnostics: Option<Arc<dyn DiagnosticsProvider>>,
    health_details: Option<Arc<dyn HealthDetailsProvider>>,
}

impl ListenerServices {
    /// Serves operational statistics from `provider`.
    #[must_use]
    pub fn with_diagnostics(mut self, provider: Arc<dyn DiagnosticsProvider>) -> Self {
        self.diagnostics = Some(provider);
        self
    }

    /// Serves detailed runtime health from `provider`.
    #[must_use]
    pub fn with_health_details(mut self, provider: Arc<dyn HealthDetailsProvider>) -> Self {
        self.health_details = Some(provider);
        self
    }
}

/// Runs the standard listener and the optional read-only `services`.
/// # Errors
/// Returns binding, serving, or cleanup errors, as with [`serve_unix`].
pub async fn serve_unix_with_services<H, B>(
    path: &Path,
    options: ListenerOptions,
    handler: Arc<H>,
    readiness: watch::Receiver<HealthStatus>,
    shutdown: watch::Receiver<bool>,
    on_bound: B,
    services: ListenerServices,
) -> anyhow::Result<()>
where
    H: Handler,
    B: FnOnce() + Send,
{
    let (listener, socket_guard) = prepare_unix_listener(path, options.socket_mode).await?;
    let incoming =
        LimitedIncoming::new(listener, options.max_connections, options.connection_lifetime);
    let _transports = incoming.close_guard();
    let request_tracker = Arc::new(RequestTracker::default());
    let grpc_service = GrpcService::new(handler, Arc::clone(&request_tracker));
    let (standard_health, health_service) = StandardHealth::new(readiness).await;
    let health_task = standard_health.run(shutdown.clone());
    tokio::pin!(health_task);
    on_bound();

    log::info!("The IPC listener accepts clients on Unix domain socket {}", path.display());

    let server = tonic::transport::Server::builder();
    let serving = server
        .max_concurrent_streams(Some(options.max_client_api_streams))
        .concurrency_limit_per_connection(options.max_client_api_streams as usize)
        .timeout(options.connection_lifetime)
        .add_service(
            TacacsAgentServer::new(grpc_service)
                .max_decoding_message_size(MAX_IPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_IPC_MESSAGE_BYTES),
        )
        .add_service(health_service)
        .add_service(
            DiagnosticsServer::new(DiagnosticsService(services.diagnostics))
                .max_decoding_message_size(2048)
                .max_encoding_message_size(MAX_IPC_MESSAGE_BYTES),
        )
        .add_optional_service(services.health_details.map(|provider| {
            AgentHealthServer::new(AgentHealthService(provider))
                .max_decoding_message_size(health_details::MAX_REQUEST_BYTES)
                .max_encoding_message_size(MAX_IPC_MESSAGE_BYTES)
        }))
        .serve_with_incoming_shutdown(incoming, wait_for_flag(shutdown.clone()));
    tokio::pin!(serving);
    tokio::select! {
        result = &mut serving => { result.with_context(|| format!("Unix IPC server {} failed", path.display()))?; }
        () = &mut health_task => { serving.await.with_context(|| format!("Unix IPC server {} failed", path.display()))?; }
    }

    log::info!("Received a shutdown signal; draining active IPC requests");
    request_tracker.wait_for_active_requests().await;
    socket_guard.cleanup().await?;
    Ok(())
}

/// Resolves when the shutdown flag becomes `true` or its sender is dropped.
async fn wait_for_flag(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};


    fn test_socket_path(socket_name: &str) -> PathBuf {
        let unique = format!(
            "{}-{}-{}.sock",
            socket_name,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("the clock must be after the Unix epoch")
                .as_nanos()
        );
        PathBuf::from("/tmp").join(unique)
    }

    async fn cleanup_paths(path: &Path) {
        let _ = tokio::fs::remove_file(path).await;
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let _ = tokio::fs::remove_file(PathBuf::from(lock_name)).await;
    }


    struct UnusedHandler;

    #[async_trait::async_trait]
    impl crate::server::Handler for UnusedHandler {
        async fn authenticate_pap(
            &self,
            _request: tacacsrs_protocol::operations::PapAuthenticationOperation,
        ) -> Result<
            tacacsrs_protocol::operations::PapAuthenticationOperationResponse,
            tacacsrs_protocol::failure::ServiceError,
        > {
            unreachable!("the test sends no operations")
        }

        async fn accounting(
            &self,
            _request: tacacsrs_protocol::operations::AccountingOperation,
        ) -> Result<
            tacacsrs_protocol::operations::AccountingOperationResponse,
            tacacsrs_protocol::failure::ServiceError,
        > {
            unreachable!("the test sends no operations")
        }

        async fn authorization(
            &self,
            _request: tacacsrs_protocol::operations::AuthorizationOperation,
        ) -> Result<
            tacacsrs_protocol::operations::AuthorizationOperationResponse,
            tacacsrs_protocol::failure::ServiceError,
        > {
            unreachable!("the test sends no operations")
        }
    }

    struct Draining;

    #[tonic::async_trait]
    impl crate::HealthDetailsProvider for Draining {
        async fn health_details(&self) -> crate::proto::HealthDetailsReply {
            let mut reply = crate::proto::HealthDetailsReply {
                liveness: true,
                ..Default::default()
            };
            reply.set_lifecycle(crate::proto::RuntimeLifecycle::Draining);
            reply.push_degradation_reasons(crate::proto::DegradationReason::DatastoreStale);
            reply
        }
    }

    /// Serves `services` on a new socket, then returns a health client.
    async fn serve_health(
        name: &str,
        services: super::ListenerServices,
    ) -> (
        PathBuf,
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        crate::HealthClient,
    ) {
        use std::sync::Arc;
        use std::time::Duration;

        use super::{HealthStatus, ListenerOptions};

        let path = test_socket_path(name);
        let options = ListenerOptions {
            socket_mode: 0o600,
            max_connections: 4,
            max_client_api_streams: 4,
            connection_lifetime: Duration::from_secs(30),
        };
        let (_, readiness) = tokio::sync::watch::channel(HealthStatus {
            startup_serving: true,
            liveness_serving: true,
            readiness_serving: false,
        });
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let (bound, is_bound) = tokio::sync::oneshot::channel();
        let socket = path.clone();
        let server = tokio::spawn(async move {
            super::serve_unix_with_services(
                &socket,
                options,
                Arc::new(UnusedHandler),
                readiness,
                shutdown,
                move || {
                    let _ = bound.send(());
                },
                services,
            )
            .await
        });
        is_bound.await.unwrap();
        let client = crate::HealthClient::connect(&crate::IpcEndpoint::Unix(path.clone()))
            .await
            .unwrap();
        (path, stop, server, client)
    }

    #[tokio::test]
    async fn health_details_are_a_route_on_the_listener_socket() {
        let services =
            super::ListenerServices::default().with_health_details(std::sync::Arc::new(Draining));
        let (path, stop, server, mut client) = serve_health("health-details", services).await;
        let reply = client.details().await.unwrap();
        assert_eq!(reply.lifecycle(), crate::proto::RuntimeLifecycle::Draining);
        assert!(reply.liveness);
        assert_eq!(
            reply.degradation_reasons().collect::<Vec<_>>(),
            [crate::proto::DegradationReason::DatastoreStale]
        );
        assert_eq!(
            client
                .check(crate::health::LIVENESS_HEALTH_SERVICE)
                .await
                .unwrap(),
            tonic_health::pb::health_check_response::ServingStatus::Serving
        );
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
        cleanup_paths(&path).await;

        let (path, stop, server, mut client) =
            serve_health("no-health-details", super::ListenerServices::default()).await;
        assert_eq!(client.details().await.unwrap_err().code(), tonic::Code::Unimplemented);
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
        cleanup_paths(&path).await;
    }

    #[tokio::test(start_paused = true)]
    async fn listener_guard_closes_retained_ipc_transports_on_cancellation() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt;
        use tokio_stream::StreamExt;

        use crate::server::limited_incoming::LimitedIncoming;

        let path = test_socket_path("cancelled-ipc");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let mut incoming = LimitedIncoming::new(listener, 1, Duration::from_secs(300));
        let guard = incoming.close_guard();
        let mut peer = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut transport = incoming.next().await.unwrap().unwrap();
        drop(guard);
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(
            transport.read(&mut [0; 1]).await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        cleanup_paths(&path).await;
    }

    #[tokio::test(start_paused = true)]
    async fn incoming_bounds_connections_and_expires_read_and_write() {
        use std::future::Future;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_stream::StreamExt;

        use crate::server::limited_incoming::LimitedIncoming;

        let path = test_socket_path("limited-ipc");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let mut incoming = LimitedIncoming::new(listener, 1, Duration::from_secs(1));
        let _first_peer = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut first = incoming.next().await.unwrap().unwrap();
        let _second_peer = tokio::net::UnixStream::connect(&path).await.unwrap();
        let next = incoming.next();
        tokio::pin!(next);
        std::future::poll_fn(|context| {
            assert!(next.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(first.read(&mut [0; 1]).await.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            first.write_all(b"reply").await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        drop(first);
        next.await.unwrap().unwrap();
        cleanup_paths(&path).await;
    }
}
