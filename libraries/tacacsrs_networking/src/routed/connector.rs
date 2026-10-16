//! Connection factories for the routed client.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{PreparedEndpoint, RequestDeadline, TacacsClient};

use super::OperationKind;

/// Supplies operation-isolated connections and their retirement behavior.
#[async_trait]
pub trait EndpointConnector: Send + Sync + 'static {
    /// Shared connection handle used by the caller's exchange implementation.
    type Connection: Send + Sync + ?Sized + 'static;

    /// Establishes a connection from prepared transport inputs.
    ///
    /// # Errors
    /// Returns an error if connection establishment fails.
    async fn connect(
        &self,
        endpoint: PreparedEndpoint,
        operation: OperationKind,
    ) -> anyhow::Result<Arc<Self::Connection>>;

    /// Retires cached sessions while allowing existing sessions to finish.
    async fn retire(&self, connection: &Self::Connection);

    /// Permanently rejects new work on this connection owner.
    fn close(&self, connection: &Self::Connection);

    /// Closes and joins the connection within the supplied retirement budget.
    ///
    /// # Errors
    /// Returns a task or I/O failure after completing resource cleanup.
    /// Implementations must stop admitting work, force cleanup at expiry, and
    /// retain cleanup ownership if this future is cancelled.
    async fn close_and_join(
        &self,
        connection: &Self::Connection,
        deadline: RequestDeadline,
    ) -> anyhow::Result<()>;
}

/// Native TACACS+ connection factory without host configuration dependencies.
#[derive(Debug, Default)]
pub struct NativeConnector;

#[async_trait]
impl EndpointConnector for NativeConnector {
    type Connection = TacacsClient;

    async fn connect(
        &self,
        endpoint: PreparedEndpoint,
        _operation: OperationKind,
    ) -> anyhow::Result<Arc<Self::Connection>> {
        TacacsClient::connect_prepared(endpoint).await.map(Arc::new)
    }

    async fn retire(&self, connection: &Self::Connection) {
        connection.stop_accepting_new_sessions().await;
    }

    fn close(&self, connection: &Self::Connection) {
        connection.close();
    }

    async fn close_and_join(
        &self,
        connection: &Self::Connection,
        deadline: RequestDeadline,
    ) -> anyhow::Result<()> {
        connection.close_and_join(deadline).await
    }
}
