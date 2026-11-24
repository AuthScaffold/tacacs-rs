//! Serves the local client API over IPC.
//!
//! The component adapts the client API handle of the agent to the IPC server
//! handler. It maps the active local services and the runtime health to the
//! IPC listener options and the IPC health signal. The listener binds, moves,
//! or stops the socket when the local services change. The same socket also
//! serves the operational statistics and the detailed runtime health. The
//! detailed health includes each check in the injected [`HealthRegistry`].
//! The component contains no routing or materialization logic.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use dill::component;
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use tokio::sync::watch;

use crate::runtime::{
    reconcile, ActiveLocalServices, BindSignal, DesiredListener, ListenerInstances,
    LocalServicesView,
};
use crate::{
    ClientApiHandle, DiagnosticsHandle, ListenerSettings, RuntimeHealthPublisher,
    RuntimeHealthSnapshot, RuntimeListenerService, RuntimeService, ShutdownReceiver,
};
use super::health_details::AgentHealthDetails;
use crate::host::{ClientApiAccess, ListenerFactory};
use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_ipc::server::{self, HealthStatus, ListenerOptions, ListenerServices};
use tacacsrs_lifecycle::HealthRegistry;
use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse, PapAuthenticationOperation, PapAuthenticationOperationResponse,
};
use tacacsrs_protocol::failure::ServiceError;

/// Adds the client API IPC listener to the agent runtime.
///
/// The listener binds only while the active local services enable the client
/// API.
pub struct ClientApiComponent;

impl Component for ClientApiComponent {
    fn name(&self) -> &'static str {
        ClientApiListenerFactory::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.member::<dyn ListenerFactory, ClientApiListenerFactory, _>(
            <ClientApiListenerFactory as dill::Component>::builder(),
        )
    }
}

/// Creates the client API IPC listener for the agent service.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn ListenerFactory)]
struct ClientApiListenerFactory {
    access: Arc<ClientApiAccess>,
    diagnostics: Arc<DiagnosticsHandle>,
    registry: Arc<HealthRegistry>,
}

impl Named for ClientApiListenerFactory {
    const NAME: &'static str = "Client API";
}

impl ListenerFactory for ClientApiListenerFactory {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn listener(&self) -> Option<Box<dyn RuntimeListenerService>> {
        Some(Box::new(ClientApiListener {
            diagnostics: Arc::new(AgentDiagnostics(DiagnosticsHandle::clone(&self.diagnostics))),
            registry: self.registry.clone(),
            handler: Arc::new(AgentClientApiHandler {
                handle: self.access.handle.clone(),
            }),
            local_services: self.access.local_services.clone(),
        }))
    }
}

/// Adapts the agent client API handle to the IPC server [`Handler`] interface.
///
/// [`Handler`]: tacacsrs_ipc::server::Handler
struct AgentClientApiHandler {
    handle: ClientApiHandle,
}

#[async_trait]
impl server::Handler for AgentClientApiHandler {
    async fn authenticate_pap(
        &self,
        request: PapAuthenticationOperation,
    ) -> Result<PapAuthenticationOperationResponse, ServiceError> {
        self.handle.authenticate_pap(request).await
    }

    async fn accounting(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        self.handle.accounting(request).await
    }

    async fn authorization(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        self.handle.authorization(request).await
    }
}

/// An injected runtime listener that serves the local client API over IPC.
struct ClientApiListener {
    handler: Arc<AgentClientApiHandler>,
    diagnostics: Arc<AgentDiagnostics>,
    registry: Arc<HealthRegistry>,
    local_services: LocalServicesView,
}

#[async_trait]
impl RuntimeListenerService for ClientApiListener {
    fn name(&self) -> &'static str {
        ClientApiListenerFactory::NAME
    }

    fn service(&self) -> Option<RuntimeService> {
        Some(RuntimeService::ClientApi)
    }

    async fn serve(
        self: Box<Self>,
        shutdown: ShutdownReceiver,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        let Self {
            handler,
            diagnostics,
            registry,
            local_services,
        } = *self;
        let instances = ClientApiInstances {
            handler,
            diagnostics,
            registry,
            health: health.clone(),
        };
        reconcile(instances, local_services.subscribe(), shutdown, health).await
    }
}

/// Starts one client API socket for each bind target.
struct ClientApiInstances {
    handler: Arc<AgentClientApiHandler>,
    diagnostics: Arc<AgentDiagnostics>,
    registry: Arc<HealthRegistry>,
    health: RuntimeHealthPublisher,
}

impl ListenerInstances for ClientApiInstances {
    type Target = (PathBuf, ListenerSettings);

    fn service(&self) -> RuntimeService {
        RuntimeService::ClientApi
    }

    fn desired(&self, local: &ActiveLocalServices) -> DesiredListener<Self::Target> {
        let prepared = local.prepared();
        match prepared.client_api() {
            Some(path) => DesiredListener::Ready((path.to_path_buf(), prepared.into())),
            None => DesiredListener::Disabled,
        }
    }

    fn conflicts(&self, active: &Self::Target, next: &Self::Target) -> bool {
        active.0 == next.0
    }

    fn start(
        &self,
        (path, settings): Self::Target,
        shutdown: ShutdownReceiver,
        bound: BindSignal,
    ) -> BoxFuture<'static, anyhow::Result<()>> {
        let handler = self.handler.clone();
        let health = self.health.clone();
        let services = ListenerServices::default()
            .with_diagnostics(self.diagnostics.clone())
            .with_health_details(Arc::new(AgentHealthDetails {
                health: health.clone(),
                registry: self.registry.clone(),
            }));
        let options = ListenerOptions {
            socket_mode: settings.socket_mode,
            max_connections: settings.max_connections,
            max_client_api_streams: settings.max_client_api_streams,
            connection_lifetime: settings.connection_lifetime,
        };
        async move {
            let (receiver, forwarder) = readiness_bridge(&health);
            let serving = server::serve_unix_with_services(
                &path,
                options,
                handler,
                receiver,
                shutdown.flag(),
                move || bound.mark_bound(),
                services,
            );
            tokio::pin!(serving);
            tokio::select! {
                result = &mut serving => result,
                () = forwarder => serving.await,
            }
        }
        .boxed()
    }
}

struct AgentDiagnostics(DiagnosticsHandle);

impl tacacsrs_ipc::DiagnosticsProvider for AgentDiagnostics {
    fn statistics_json(
        &self,
        server: Option<&str>,
        maximum_bytes: usize,
    ) -> anyhow::Result<String> {
        self.0.statistics_json(server, maximum_bytes)
    }
}

fn readiness_bridge(
    health: &RuntimeHealthPublisher,
) -> (watch::Receiver<HealthStatus>, impl Future<Output = ()> + Send + 'static) {
    let mut snapshot_receiver = health.subscribe();
    let (sender, receiver) = watch::channel(health_status(&snapshot_receiver.borrow()));
    let forwarder = async move {
        while snapshot_receiver.changed().await.is_ok() {
            let status = health_status(&snapshot_receiver.borrow());
            if sender.send(status).is_err() {
                break;
            }
        }
    };
    (receiver, forwarder)
}

fn health_status(snapshot: &RuntimeHealthSnapshot) -> HealthStatus {
    HealthStatus {
        startup_serving: snapshot.is_startup_serving(),
        liveness_serving: snapshot.is_liveness_serving(),
        readiness_serving: snapshot.is_readiness_serving(),
    }
}
