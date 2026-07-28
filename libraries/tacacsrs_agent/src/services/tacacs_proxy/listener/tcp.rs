//! Loopback TCP listener for raw TACACS+ proxy clients.

use std::net::SocketAddr;

use anyhow::{Context, bail};

use super::{ProxyListener, accept_loop};
use crate::runtime::{ListenerRegistration, ShutdownReceiver};
use crate::services::tacacs_proxy::TacacsProxyService;

pub(super) async fn serve(
    address: SocketAddr,
    service: TacacsProxyService,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
) -> anyhow::Result<()> {
    if !address.ip().is_loopback() {
        log::error!("Refusing non-loopback TCP TACACS+ proxy endpoint: {address}");
        bail!("TCP TACACS+ proxy endpoint must be loopback-only: {address}");
    }

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to bind TCP TACACS+ proxy endpoint {address}"))?;
    let local_address = listener
        .local_addr()
        .with_context(|| format!("Failed to inspect TCP TACACS+ proxy endpoint {address}"))?;
    registration.mark_bound();

    log::info!("Listening for TACACS+ proxy clients on TCP {local_address}");
    accept_loop(listener, service, format!("TCP {local_address}"), shutdown).await
}

#[async_trait::async_trait]
impl ProxyListener<tokio::net::TcpStream> for tokio::net::TcpListener {
    async fn accept_proxy_stream(&self) -> anyhow::Result<(tokio::net::TcpStream, String)> {
        let (stream, address) = self
            .accept()
            .await
            .context("Failed to accept TCP TACACS+ proxy connection")?;
        Ok((stream, address.to_string()))
    }
}
