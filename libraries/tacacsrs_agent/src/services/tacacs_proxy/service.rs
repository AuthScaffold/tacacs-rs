//! Service object for the raw TACACS+ proxy.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use tacacsrs_config::local_services::ListenerEndpoint;
use tokio::io::{AsyncRead, AsyncWrite};

use super::listener;
use super::upstream_bridge::UpstreamBridge;
use crate::runtime::{
    endpoints_conflict, reconcile, ActiveLocalServices, BindSignal, DesiredListener,
    ListenerInstances, LocalServicesView, ProxyListenerBinding, ProxyLoopGuard,
    RuntimeHealthPublisher, RuntimeListenerService, RuntimeService, ShutdownReceiver,
};
use crate::services::ListenerOptions;
use crate::upstream::manager::UpstreamManager;
use crate::upstream::UpstreamConnection;
use tacacsrs_networking::routed::EndpointConnector;

/// Owns the raw TACACS+ proxy runtime dependencies.
pub(crate) struct TacacsProxyService<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    upstream_bridge: UpstreamBridge<Connector>,
    proxy_loop_guard: ProxyLoopGuard,
}

impl<Connector: EndpointConnector> Clone for TacacsProxyService<Connector> {
    fn clone(&self) -> Self {
        Self {
            upstream_bridge: self.upstream_bridge.clone(),
            proxy_loop_guard: self.proxy_loop_guard.clone(),
        }
    }
}

impl<Connector: EndpointConnector> TacacsProxyService<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    /// Creates a raw TACACS+ proxy service with shared runtime state.
    pub(crate) fn new(
        upstream_manager: Arc<UpstreamManager<Connector>>,
        proxy_loop_guard: ProxyLoopGuard,
    ) -> Self {
        Self {
            upstream_bridge: UpstreamBridge::new(upstream_manager),
            proxy_loop_guard,
        }
    }

    pub(super) fn bind_proxy_listener(
        &self,
        address: std::net::SocketAddr,
    ) -> anyhow::Result<ProxyListenerBinding> {
        self.proxy_loop_guard.bind(address)
    }

    pub(super) async fn handle_connection<Stream>(
        &self,
        stream: Stream,
        peer_label: String,
    ) -> anyhow::Result<()>
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.upstream_bridge
            .handle_connection(stream, peer_label)
            .await
    }
}

impl<Connector: EndpointConnector + 'static> ListenerInstances for TacacsProxyService<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    type Target = (ListenerEndpoint, ListenerOptions);

    fn service(&self) -> RuntimeService {
        RuntimeService::TacacsProxy
    }

    fn desired(&self, local: &ActiveLocalServices) -> DesiredListener<Self::Target> {
        let prepared = local.prepared();
        match prepared.tacacs_proxy() {
            Some(endpoint) => {
                DesiredListener::Ready((endpoint.clone(), ListenerOptions::new(prepared)))
            }
            None if prepared.tacacs_proxy_enabled() => DesiredListener::Waiting,
            None => DesiredListener::Disabled,
        }
    }

    fn conflicts(&self, active: &Self::Target, next: &Self::Target) -> bool {
        endpoints_conflict(&active.0, &next.0)
    }

    fn start(
        &self,
        (endpoint, options): Self::Target,
        shutdown: ShutdownReceiver,
        bound: BindSignal,
    ) -> BoxFuture<'static, anyhow::Result<()>> {
        listener::serve(endpoint, self.clone(), options, shutdown, bound).boxed()
    }
}

/// Host-selectable listener for the raw TACACS+ proxy.
///
/// The listener follows the active local services. It binds, moves, and
/// stops the proxy endpoint when the local services change.
pub(crate) struct TacacsProxyListener<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    service: TacacsProxyService<Connector>,
    local_services: LocalServicesView,
}

impl<Connector: EndpointConnector> TacacsProxyListener<Connector> {
    pub(crate) fn new(
        service: TacacsProxyService<Connector>,
        local_services: LocalServicesView,
    ) -> Self {
        Self {
            service,
            local_services,
        }
    }
}

#[async_trait]
impl<Connector: EndpointConnector + 'static> RuntimeListenerService
    for TacacsProxyListener<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    fn name(&self) -> &'static str {
        "TACACS+ proxy"
    }

    fn service(&self) -> Option<RuntimeService> {
        Some(RuntimeService::TacacsProxy)
    }

    async fn serve(
        self: Box<Self>,
        shutdown: ShutdownReceiver,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        let Self {
            service,
            local_services,
        } = *self;
        reconcile(service, local_services.subscribe(), shutdown, health).await
    }
}
