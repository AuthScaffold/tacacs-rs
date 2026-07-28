//! TACACS+ proxy endpoint dispatch and accept loop.

use tacacsrs_agent_client::IpcEndpoint;
use tokio::io::{AsyncRead, AsyncWrite};

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
                tokio::spawn(async move {
                    if let Err(error) = service.handle_connection(stream, peer_label.clone(), request_guard).await {
                        log::warn!("TACACS+ proxy connection {peer_label} closed with error: {error:#}");
                    }
                });
            }
        }
    }

    service.wait_for_active_requests().await;
    Ok(())
}

#[async_trait::async_trait]
trait ProxyListener<Stream>: Send + Sync {
    async fn accept_proxy_stream(&self) -> anyhow::Result<(Stream, String)>;
}
