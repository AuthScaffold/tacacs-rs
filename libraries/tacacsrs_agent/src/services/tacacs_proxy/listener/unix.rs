//! Unix domain socket listener for raw TACACS+ proxy clients.

use std::path::Path;

use anyhow::Context;

use super::{ProxyListener, accept_loop};
use crate::runtime::{ListenerRegistration, ShutdownReceiver};
use crate::services::client_api::listener as client_api_listener;
use crate::services::tacacs_proxy::TacacsProxyService;

pub(super) async fn serve(
    path: &Path,
    service: TacacsProxyService,
    socket_mode: u32,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
) -> anyhow::Result<()> {
    let (listener, socket_guard) =
        client_api_listener::prepare_unix_listener(path, socket_mode).await?;
    registration.mark_bound();

    log::info!("Listening for TACACS+ proxy clients on Unix socket {}", path.display());
    let result =
        accept_loop(listener, service, format!("Unix socket {}", path.display()), shutdown).await;
    socket_guard.cleanup("TACACS+ proxy Unix socket").await?;
    result
}

#[async_trait::async_trait]
impl ProxyListener<tokio::net::UnixStream> for tokio::net::UnixListener {
    async fn accept_proxy_stream(&self) -> anyhow::Result<(tokio::net::UnixStream, String)> {
        let (stream, address) = self
            .accept()
            .await
            .context("Failed to accept Unix TACACS+ proxy connection")?;
        let peer_label = address
            .as_pathname()
            .map_or_else(|| "anonymous-unix-peer".to_owned(), |path| path.display().to_string());
        Ok((stream, peer_label))
    }
}
