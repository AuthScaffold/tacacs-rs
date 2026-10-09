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

pub(super) async fn serve<Connector: tacacsrs_networking::routed::EndpointConnector>(
    endpoint: &IpcEndpoint,
    service: TacacsProxyService<Connector>,
    options: ListenerOptions,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
) -> anyhow::Result<()>
where
    Connector::Connection: crate::upstream::UpstreamConnection,
{
    match endpoint {
        IpcEndpoint::Unix(path) => {
            unix::serve(path, service, options, shutdown, registration).await
        }
        IpcEndpoint::Tcp(address) => {
            tcp::serve(*address, service, options, shutdown, registration).await
        }
    }
}

/// Time for active proxy connections to finish before forced cancellation.
///
/// This limit prevents a client from delaying process termination with
/// continuous valid traffic. It gives a normal authorization or accounting
/// exchange time to finish.
const PROXY_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

async fn accept_loop<Listener, Stream, Connector: tacacsrs_networking::routed::EndpointConnector>(
    listener: Listener,
    service: TacacsProxyService<Connector>,
    endpoint_label: String,
    options: ListenerOptions,
    shutdown: ShutdownReceiver,
) -> anyhow::Result<()>
where
    Listener: ProxyListener<Stream>,
    Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Connector::Connection: crate::upstream::UpstreamConnection,
{
    let mut shutdown = Box::pin(shutdown.wait());
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => {
                log::info!("Received a shutdown signal; stopping the TACACS+ proxy listener on {endpoint_label}");
                break;
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    log::warn!("A TACACS+ proxy connection task stopped: {error}");
                }
            }
            accepted = listener.accept_proxy_stream(), if connections.len() < options.max_connections => {
                let (stream, peer_label) = accepted?;
                let request_guard = service.start_request();
                let service = service.clone();
                connections.spawn(async move {
                    let result = tokio::time::timeout(options.connection_lifetime,
                        service.handle_connection(stream, peer_label.clone(), request_guard)).await;
                    if let Err(error) = result.map_err(anyhow::Error::from).and_then(std::convert::identity) {
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

    struct QueuedListener {
        streams: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<tokio::io::DuplexStream>>,
        accepted: Arc<tokio::sync::Notify>,
        count: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl super::ProxyListener<tokio::io::DuplexStream> for QueuedListener {
        async fn accept_proxy_stream(&self) -> anyhow::Result<(tokio::io::DuplexStream, String)> {
            let stream = self.streams.lock().await.recv().await.unwrap();
            self.count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.accepted.notify_one();
            Ok((stream, "test-peer".to_owned()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connection_limit_resumes_after_expiry_and_reaps_completed_tasks() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use crate::runtime::{ProxyLoopGuard, RuntimeHealthPublisher, ShutdownCoordinator};
        use crate::services::ListenerOptions;
        use crate::test_support::FakeConnector;
        use crate::upstream::manager::UpstreamManager;

        let health = RuntimeHealthPublisher::new(crate::EnabledServices::TACACS_PROXY);
        let shutdown = ShutdownCoordinator::new(health.clone());
        let manager = Arc::new(UpstreamManager::new(
            vec![],
            Arc::new(FakeConnector::new(std::collections::HashMap::new())),
            Duration::from_secs(30),
            health,
        ));
        let service = super::TacacsProxyService::new(
            manager,
            Arc::new(RequestTracker::default()),
            ProxyLoopGuard::new(None),
        );
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let (first, first_peer) = tokio::io::duplex(256);
        let (second, second_peer) = tokio::io::duplex(256);
        sender.send(first).await.unwrap();
        sender.send(second).await.unwrap();
        let accepted = Arc::new(tokio::sync::Notify::new());
        let count = Arc::new(AtomicUsize::new(0));
        let listener = QueuedListener {
            streams: tokio::sync::Mutex::new(receiver),
            accepted: accepted.clone(),
            count: count.clone(),
        };
        let prepared = tacacsrs_config::local_services::prepare_local_services(
            &tacacsrs_config::tacacsrs::LocalServices {
                max_connections: 1,
                connection_lifetime_seconds: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let task = tokio::spawn(super::accept_loop(
            listener,
            service,
            "test".to_owned(),
            ListenerOptions::new(&prepared),
            shutdown.subscribe(),
        ));
        accepted.notified().await;
        assert_eq!(count.load(Ordering::Acquire), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        accepted.notified().await;
        assert_eq!(count.load(Ordering::Acquire), 2);
        shutdown.initiate_shutdown();
        drop((first_peer, second_peer));
        task.await.unwrap().unwrap();
    }

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
