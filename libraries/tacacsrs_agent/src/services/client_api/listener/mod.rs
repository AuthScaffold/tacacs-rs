//! Local client API endpoint dispatch.

#[cfg(unix)]
use anyhow::bail;
use tacacsrs_agent_client::IpcEndpoint;
use tokio::sync::watch;

use super::ClientApiService;
use crate::runtime::{ListenerRegistration, RuntimeHealthSnapshot, ShutdownReceiver};
use crate::services::ListenerOptions;

#[cfg(not(unix))]
mod tcp;
#[cfg(unix)]
mod unix;

#[cfg(unix)]
/// Serves the configured local client API endpoint until process shutdown is signalled.
pub(crate) async fn serve(
    endpoint: &IpcEndpoint,
    service: ClientApiService,
    options: ListenerOptions,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
    health: watch::Receiver<RuntimeHealthSnapshot>,
) -> anyhow::Result<()> {
    match endpoint {
        IpcEndpoint::Unix(path) => {
            unix::serve(
                path,
                service,
                options.socket_mode(),
                shutdown,
                registration,
                health,
            )
            .await
        }
        IpcEndpoint::Tcp(address) => bail!(
            "Unix client API endpoints must use a Unix domain socket; TCP endpoint {address} is only supported for the TACACS+ proxy on Unix"
        ),
    }
}

#[cfg(unix)]
pub(crate) fn validate_endpoint(endpoint: &IpcEndpoint) -> anyhow::Result<()> {
    if let IpcEndpoint::Tcp(address) = endpoint {
        bail!(
            "Unix client API endpoints must use a Unix domain socket; TCP endpoint {address} is only supported for the TACACS+ proxy on Unix"
        );
    }

    Ok(())
}

#[cfg(not(unix))]
/// Serves the configured local client API endpoint until process shutdown is signalled.
pub(crate) async fn serve(
    endpoint: &IpcEndpoint,
    service: ClientApiService,
    _options: ListenerOptions,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
    health: watch::Receiver<RuntimeHealthSnapshot>,
) -> anyhow::Result<()> {
    match endpoint {
        IpcEndpoint::Tcp(address) => {
            tcp::serve(*address, service, shutdown, registration, health).await
        }
    }
}

#[cfg(unix)]
pub(crate) use unix::{UnixSocketCleanupGuard, prepare_unix_listener};
