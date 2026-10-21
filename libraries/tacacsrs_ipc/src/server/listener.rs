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
use crate::proto::tacacs_agent_server::TacacsAgentServer;

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
    serve_unix_with_diagnostics(path, options, handler, readiness, shutdown, on_bound, None).await
}

/// Runs the standard listener with an optional read-only diagnostics provider.
/// # Errors
/// Returns binding, serving, or cleanup errors, as with [`serve_unix`].
pub async fn serve_unix_with_diagnostics<H, B>(
    path: &Path,
    options: ListenerOptions,
    handler: Arc<H>,
    readiness: watch::Receiver<HealthStatus>,
    shutdown: watch::Receiver<bool>,
    on_bound: B,
    diagnostics: Option<Arc<dyn crate::DiagnosticsProvider>>,
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
            crate::proto::diagnostics_server::DiagnosticsServer::new(
                crate::diagnostics::DiagnosticsService(diagnostics),
            )
            .max_decoding_message_size(2048)
            .max_encoding_message_size(MAX_IPC_MESSAGE_BYTES),
        )
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
