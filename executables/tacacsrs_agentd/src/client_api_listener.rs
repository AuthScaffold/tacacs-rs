//! Composes the local client API IPC listener with the agent runtime.
//!
//! The daemon adapts the agent client API handle to the IPC server handler and
//! injects an IPC listener into the agent runtime. The daemon maps the agent's
//! prepared listener settings and health projection into the transport-neutral
//! IPC options and health signal. No routing or materialization logic lives
//! here.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;

use tacacsrs_agent::{
    ClientApiHandle, ListenerRegistration, ListenerState, RuntimeHealthPublisher,
    RuntimeHealthSnapshot, RuntimeListenerService, RuntimeService, ShutdownReceiver,
    TacacsClientService,
};
use tacacsrs_ipc::server::{self, HealthStatus, ListenerOptions};
use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse, PapAuthenticationOperation, PapAuthenticationOperationResponse,
    ServiceError,
};

/// Builds the injected runtime listeners for the local client API.
///
/// Returns one IPC listener when the client API is enabled, otherwise an empty
/// set. The raw TACACS+ proxy remains an internal agent runtime listener.
pub fn client_api_listeners(service: &TacacsClientService) -> Vec<Box<dyn RuntimeListenerService>> {
    match service.client_api_socket_path() {
        Some(path) => {
            let settings = service.client_api_listener_settings();
            let listener = ClientApiListener {
                handler: Arc::new(AgentClientApiHandler {
                    handle: service.client_api_handle(),
                }),
                path,
                options: ListenerOptions {
                    socket_mode: settings.socket_mode,
                    max_connections: settings.max_connections,
                    max_client_api_streams: settings.max_client_api_streams,
                    connection_lifetime: settings.connection_lifetime,
                },
            };
            vec![Box::new(listener)]
        }
        None => Vec::new(),
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
    path: PathBuf,
    options: ListenerOptions,
}

#[async_trait]
impl RuntimeListenerService for ClientApiListener {
    async fn serve(
        self: Box<Self>,
        shutdown: ShutdownReceiver,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        let Self {
            handler,
            path,
            options,
        } = *self;
        let registration = ListenerRegistration::new(health.clone(), RuntimeService::ClientApi);
        let (receiver, forwarder) = readiness_bridge(&health);
        let bound_health = health.clone();
        let on_bound = move || {
            let _ = bound_health.set_listener(RuntimeService::ClientApi, ListenerState::Bound);
        };
        let serving =
            server::serve_unix(&path, options, handler, receiver, shutdown.flag(), on_bound);
        tokio::pin!(serving);
        let result = tokio::select! {
            result = &mut serving => result,
            () = forwarder => serving.await,
        };
        drop(registration);
        result
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
