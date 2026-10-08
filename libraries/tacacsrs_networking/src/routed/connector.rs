//! Connection factories for the routed client.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{PreparedEndpoint, TacacsClient};

use super::OperationKind;

/// Supplies operation-isolated connections and their retirement behavior.
#[async_trait]
pub trait EndpointConnector: Send + Sync {
    /// Shared connection handle used by the caller's exchange implementation.
    type Connection: Send + Sync + ?Sized;

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
}
