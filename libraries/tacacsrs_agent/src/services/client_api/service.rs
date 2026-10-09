//! Service object for the local client API.

use std::sync::Arc;

use tacacsrs_agent_client::IpcEndpoint;

use super::GrpcService;
use super::listener;
use crate::runtime::{
    ListenerRegistration, RequestTracker, RuntimeHealthPublisher, RuntimeService, ShutdownReceiver,
};
use crate::services::ListenerOptions;
use crate::upstream::manager::UpstreamManager;
use crate::upstream::UpstreamConnection;
use tacacsrs_networking::routed::EndpointConnector;

/// Owns the local client API runtime dependencies.
pub(crate) struct ClientApiService<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    grpc_service: GrpcService<Connector>,
    request_tracker: Arc<RequestTracker>,
}

impl<Connector: EndpointConnector> Clone for ClientApiService<Connector> {
    fn clone(&self) -> Self {
        Self {
            grpc_service: self.grpc_service.clone(),
            request_tracker: self.request_tracker.clone(),
        }
    }
}

impl<Connector: EndpointConnector> ClientApiService<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    /// Creates a local client API service over shared runtime state.
    pub(crate) fn new(
        upstream_manager: Arc<UpstreamManager<Connector>>,
        request_tracker: Arc<RequestTracker>,
    ) -> Self {
        Self {
            grpc_service: GrpcService::new(upstream_manager, Arc::clone(&request_tracker)),
            request_tracker,
        }
    }

    /// Runs the client API listener until the process receives a shutdown signal.
    pub(crate) async fn serve(
        &self,
        endpoint: &IpcEndpoint,
        options: ListenerOptions,
        shutdown: ShutdownReceiver,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        let health_receiver = health.subscribe();
        let registration = ListenerRegistration::new(health, RuntimeService::ClientApi);
        listener::serve(endpoint, self.clone(), options, shutdown, registration, health_receiver)
            .await
    }

    pub(super) fn grpc_service(&self) -> GrpcService<Connector> {
        self.grpc_service.clone()
    }

    pub(super) async fn wait_for_active_requests(&self) {
        self.request_tracker.wait_for_active_requests().await;
    }
}
