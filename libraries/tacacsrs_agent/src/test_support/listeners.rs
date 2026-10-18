//! Test runtime listeners for agent serve-orchestration tests.
//!
//! These doubles exercise the runtime listener injection point. One runs the
//! real IPC client API listener over the shared upstream manager. The other
//! blocks its drain so a test can observe health withdrawal before the drain
//! completes. The agent keeps the IPC crate as a development dependency only for
//! these integration tests.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use tacacsrs_ipc::server::{self, HealthStatus, ListenerOptions};
use tacacsrs_networking::routed::EndpointConnector;
use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse, PapAuthenticationOperation, PapAuthenticationOperationResponse,
};
use tacacsrs_protocol::failure::ServiceError;

use crate::ListenerState;
use crate::runtime::{
    ListenerRegistration, RuntimeHealthPublisher, RuntimeHealthSnapshot, RuntimeListenerService,
    RuntimeService, ShutdownReceiver,
};
use crate::services::client_api::UpstreamBridge;
use crate::upstream::UpstreamConnection;
use crate::upstream::manager::UpstreamManager;

/// Forwards decoded IPC operations to the shared upstream bridge.
struct TestClientApiHandler<Connector: EndpointConnector> {
    bridge: UpstreamBridge<Connector>,
}

#[async_trait]
impl<Connector: EndpointConnector + 'static> server::Handler for TestClientApiHandler<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    async fn authenticate_pap(
        &self,
        request: PapAuthenticationOperation,
    ) -> Result<PapAuthenticationOperationResponse, ServiceError> {
        self.bridge
            .execute_pap_authentication_request(request)
            .await
    }

    async fn accounting(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        self.bridge.execute_accounting_request(request).await
    }

    async fn authorization(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        self.bridge.execute_authorization_request(request).await
    }
}

/// Runs the real IPC client API listener as an injected runtime listener.
pub(crate) struct TestClientApiListener<Connector: EndpointConnector> {
    handler: Arc<TestClientApiHandler<Connector>>,
    path: PathBuf,
    options: ListenerOptions,
}

impl<Connector: EndpointConnector + 'static> TestClientApiListener<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    /// Creates a boxed client API listener over the shared upstream manager.
    pub(crate) fn boxed(
        state: Arc<UpstreamManager<Connector>>,
        path: PathBuf,
        options: ListenerOptions,
    ) -> Box<dyn RuntimeListenerService> {
        Box::new(Self {
            handler: Arc::new(TestClientApiHandler {
                bridge: UpstreamBridge::new(state),
            }),
            path,
            options,
        })
    }
}

#[async_trait]
impl<Connector: EndpointConnector + 'static> RuntimeListenerService
    for TestClientApiListener<Connector>
where
    Connector::Connection: UpstreamConnection,
{
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
        let mut snapshot_receiver = health.subscribe();
        let (sender, receiver) = watch::channel(health_status(&snapshot_receiver.borrow()));
        let forwarder = ForwarderGuard(tokio::spawn(async move {
            while snapshot_receiver.changed().await.is_ok() {
                if sender
                    .send(health_status(&snapshot_receiver.borrow()))
                    .is_err()
                {
                    break;
                }
            }
        }));
        let bound_health = health.clone();
        let on_bound = move || {
            let _ = bound_health.set_listener(RuntimeService::ClientApi, ListenerState::Bound);
        };
        let result =
            server::serve_unix(&path, options, handler, receiver, shutdown.flag(), on_bound).await;
        drop(forwarder);
        drop(registration);
        result
    }
}

/// Aborts the readiness forwarder task when the listener stops.
struct ForwarderGuard(JoinHandle<()>);

impl Drop for ForwarderGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn health_status(snapshot: &RuntimeHealthSnapshot) -> HealthStatus {
    HealthStatus {
        startup_serving: snapshot.is_startup_serving(),
        liveness_serving: snapshot.is_liveness_serving(),
        readiness_serving: snapshot.is_readiness_serving(),
    }
}

/// A client API listener whose drain blocks until a test releases it.
///
/// The listener reports `Bound`, waits for shutdown, and then waits on a shared
/// notification before it returns. A test uses this to observe that the runtime
/// withdraws health before the drain completes.
pub(crate) struct BlockingClientApiListener {
    release: Arc<Notify>,
}

impl BlockingClientApiListener {
    /// Creates a blocking listener and the notification that releases its drain.
    pub(crate) fn pair() -> (Box<dyn RuntimeListenerService>, Arc<Notify>) {
        let release = Arc::new(Notify::new());
        let listener = Box::new(Self {
            release: Arc::clone(&release),
        });
        (listener, release)
    }
}

#[async_trait]
impl RuntimeListenerService for BlockingClientApiListener {
    async fn serve(
        self: Box<Self>,
        shutdown: ShutdownReceiver,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<()> {
        let registration = ListenerRegistration::new(health, RuntimeService::ClientApi);
        registration.mark_bound();
        shutdown.wait().await;
        self.release.notified().await;
        drop(registration);
        Ok(())
    }
}
