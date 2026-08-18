//! TACACS+ proxy endpoint dispatch and accept loop.

use std::time::Duration;

use tacacsrs_agent_client::IpcEndpoint;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;

use super::TacacsProxyService;
use crate::runtime::{ListenerRegistration, ShutdownReceiver};
use crate::services::ListenerOptions;

mod tcp;
mod unix;

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

/// Time for active proxy connections to finish before forced cancellation.
///
/// This limit prevents a client from delaying process termination with
/// continuous valid traffic. It gives a normal authorization or accounting
/// exchange time to finish.
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
                log::info!("Received a shutdown signal; stopping the TACACS+ proxy listener on {endpoint_label}");
                break;
            }
            accepted = listener.accept_proxy_stream() => {
                let (stream, peer_label) = accepted?;
                let request_guard = service.start_request();
                let service = service.clone();
                connections.spawn(async move {
                    if let Err(error) = service.handle_connection(stream, peer_label.clone(), request_guard).await {
                        log::warn!("TACACS+ proxy connection {peer_label} stopped with an error: {error:#}");
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
/// Active connections have `grace` to finish. When the time expires, this
/// function cancels and joins the remaining tasks. Thus, a downstream client
/// cannot make shutdown exceed the limit.
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
                    "The shutdown time limit expired; cancelling {} active TACACS+ proxy connection(s) on {endpoint_label}",
                    connections.len()
                );
                connections.shutdown().await;
                return;
            }
            result = connections.join_next() => {
                if result.is_none() {
                    log::debug!("All active TACACS+ proxy connections stopped on {endpoint_label}");
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
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio time.
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
            "a short request must finish before the shutdown time limit"
        );
        tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
            .await
            .expect("the request tracker must reach zero after a clean drain");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio time.
    async fn drain_aborts_connections_that_outlast_the_grace_period() {
        let tracker = Arc::new(RequestTracker::default());
        let guard = tracker.start_request();
        let mut connections = JoinSet::new();
        connections.spawn(async move {
            let _guard = guard;
            // Model a client that sends valid traffic continuously.
            std::future::pending::<()>().await;
        });

        let start = Instant::now();
        drain_connections(connections, Duration::from_millis(50), "test").await;

        assert!(
            start.elapsed() < Duration::from_secs(2),
            "drain must return soon after the shutdown time limit"
        );
        tokio::time::timeout(Duration::from_millis(100), tracker.wait_for_active_requests())
            .await
            .expect("cancelling the connection must drop its guard");
    }
}
