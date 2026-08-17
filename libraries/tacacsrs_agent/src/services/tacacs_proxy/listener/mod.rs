//! TACACS+ proxy endpoint dispatch and accept loop.

use std::time::Duration;

use tacacsrs_agent_client::IpcEndpoint;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;

use super::TacacsProxyService;
use crate::runtime::{ListenerRegistration, ShutdownReceiver};
use crate::services::ListenerOptions;

mod tcp;
#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub(super) async fn serve(
    endpoint: &IpcEndpoint,
    service: TacacsProxyService,
    options: ListenerOptions,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
) -> anyhow::Result<()> {
    match endpoint {
        IpcEndpoint::Unix(path) => {
            unix::serve(path, service, options.socket_mode(), shutdown, registration).await
        }
        IpcEndpoint::Tcp(address) => tcp::serve(*address, service, shutdown, registration).await,
    }
}

#[cfg(not(unix))]
pub(super) async fn serve(
    endpoint: &IpcEndpoint,
    service: TacacsProxyService,
    _options: ListenerOptions,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
) -> anyhow::Result<()> {
    match endpoint {
        IpcEndpoint::Tcp(address) => tcp::serve(*address, service, shutdown, registration).await,
    }
}

/// Grace period for in-flight proxy connections to finish after shutdown begins
/// before they are force-aborted.
///
/// Bounds process exit: a client that keeps sending valid traffic after
/// shutdown cannot delay termination beyond this window. Sized to let a normal
/// in-flight authorization or accounting exchange complete while staying well
/// under a typical container termination grace period.
const PROXY_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

async fn accept_loop<Listener, Stream>(
    listener: Listener,
    service: TacacsProxyService,
    endpoint_label: String,
    shutdown: ShutdownReceiver,
) -> anyhow::Result<()>
where
    Listener: ProxyListener<Stream>,
    Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut shutdown = Box::pin(shutdown.wait());
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            () = &mut shutdown => {
                log::info!("Shutdown signal received; stopping TACACS+ proxy listener on {endpoint_label}");
                break;
            }
            accepted = listener.accept_proxy_stream() => {
                let (stream, peer_label) = accepted?;
                let request_guard = service.start_request();
                let service = service.clone();
                connections.spawn(async move {
                    if let Err(error) = service.handle_connection(stream, peer_label.clone(), request_guard).await {
                        log::warn!("TACACS+ proxy connection {peer_label} closed with error: {error:#}");
                    }
                });
            }
        }
    }

    drain_connections(connections, PROXY_SHUTDOWN_GRACE, &endpoint_label).await;
    service.wait_for_active_requests().await;
    Ok(())
}

/// Drains owned proxy connection tasks with a bounded grace period.
///
/// In-flight connections are given `grace` to finish on their own; any that are
/// still running when the deadline elapses are aborted and joined, so shutdown
/// always completes within the bound regardless of downstream client behaviour.
async fn drain_connections(mut connections: JoinSet<()>, grace: Duration, endpoint_label: &str) {
    if connections.is_empty() {
        return;
    }

    let deadline = tokio::time::sleep(grace);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            () = &mut deadline => {
                log::warn!(
                    "Grace period elapsed; aborting {} in-flight TACACS+ proxy connection(s) on {endpoint_label}",
                    connections.len()
                );
                connections.shutdown().await;
                return;
            }
            result = connections.join_next() => {
                if result.is_none() {
                    log::debug!("All in-flight TACACS+ proxy connections drained on {endpoint_label}");
                    return;
                }
            }
        }
    }
}

#[async_trait::async_trait]
trait ProxyListener<Stream>: Send + Sync {
    async fn accept_proxy_stream(&self) -> anyhow::Result<(Stream, String)>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::task::JoinSet;

    use super::drain_connections;
    use crate::runtime::RequestTracker;

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio time not supported
    async fn drain_lets_short_requests_finish_before_the_deadline() {
        let tracker = Arc::new(RequestTracker::default());
        let guard = tracker.start_request();
        let mut connections = JoinSet::new();
        connections.spawn(async move {
            let _guard = guard;
            tokio::time::sleep(Duration::from_millis(20)).await;
        });

        let start = Instant::now();
        drain_connections(connections, Duration::from_secs(5), "test").await;

        assert!(
            start.elapsed() < Duration::from_secs(1),
            "a short request should finish well before the grace deadline"
        );
        tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
            .await
            .expect("request tracker should reach zero after a clean drain");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio time not supported
    async fn drain_aborts_connections_that_outlast_the_grace_period() {
        let tracker = Arc::new(RequestTracker::default());
        let guard = tracker.start_request();
        let mut connections = JoinSet::new();
        connections.spawn(async move {
            let _guard = guard;
            // Never completes on its own, modelling a client that keeps sending valid traffic.
            std::future::pending::<()>().await;
        });

        let start = Instant::now();
        drain_connections(connections, Duration::from_millis(50), "test").await;

        assert!(
            start.elapsed() < Duration::from_secs(2),
            "drain must return shortly after the grace deadline"
        );
        tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
            .await
            .expect("aborting the connection must drop its guard so the tracker reaches zero");
    }
}
