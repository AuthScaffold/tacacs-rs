//! Service object for the raw TACACS+ proxy.

use std::sync::Arc;

use tacacsrs_agent_client::IpcEndpoint;
use tokio::io::{AsyncRead, AsyncWrite};

use super::listener;
use super::upstream_bridge::UpstreamBridge;
use crate::runtime::{
    ListenerRegistration, RequestGuard, RequestTracker, RuntimeHealthPublisher, RuntimeService,
    ShutdownReceiver,
};
use crate::services::ListenerOptions;
use crate::upstream::manager::UpstreamManager;

/// Owns the raw TACACS+ proxy runtime dependencies.
#[derive(Clone)]
pub(crate) struct TacacsProxyService {
    request_tracker: Arc<RequestTracker>,
    upstream_bridge: UpstreamBridge,
}

impl TacacsProxyService {
    /// Creates a raw TACACS+ proxy service with shared runtime state.
    pub(crate) fn new(
        upstream_manager: Arc<UpstreamManager>,
        request_tracker: Arc<RequestTracker>,
    ) -> Self {
        Self {
            request_tracker,
            upstream_bridge: UpstreamBridge::new(upstream_manager),
        }
    }

    /// Runs the TACACS+ proxy listener until the process receives a shutdown signal.
    pub(crate) async fn serve(
        &self,
        endpoint: &IpcEndpoint,
        options: ListenerOptions,
        shutdown: ShutdownReceiver,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        let registration = ListenerRegistration::new(health, RuntimeService::TacacsProxy);
        listener::serve(endpoint, self.clone(), options, shutdown, registration).await
    }

    pub(super) async fn handle_connection<Stream>(
        &self,
        stream: Stream,
        peer_label: String,
        request_guard: RequestGuard,
    ) -> anyhow::Result<()>
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.upstream_bridge
            .handle_connection(stream, peer_label, request_guard)
            .await
    }

    pub(super) fn start_request(&self) -> RequestGuard {
        self.request_tracker.start_request()
    }

    pub(super) async fn wait_for_active_requests(&self) {
        self.request_tracker.wait_for_active_requests().await;
    }
}
