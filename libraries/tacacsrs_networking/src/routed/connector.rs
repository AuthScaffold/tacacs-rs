//! Connection factories for the routed client.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{PreparedEndpoint, RequestDeadline, TacacsClient};

use super::OperationKind;

/// Supplies shared endpoint connections and their retirement behavior.
///
/// The routed client caches one connection per endpoint. Every operation that
/// routes to the endpoint uses that connection, so it must accept
/// authentication, authorization, and accounting sessions.
#[async_trait]
pub trait EndpointConnector: Send + Sync + 'static {
    /// Shared connection handle used by the caller's exchange implementation.
    type Connection: Send + Sync + ?Sized + 'static;

    /// Establishes a connection from prepared transport inputs.
    ///
    /// `operation` names the operation whose binding started this attempt.
    /// Use it for diagnostics only. The connection serves every operation.
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
///
/// An optional revocation verifier is attached to every endpoint that the
/// connector opens. See [`crate::revocation`].
#[derive(Clone, Default)]
pub struct NativeConnector {
    revocation_verifier: Option<Arc<dyn crate::RevocationVerifier>>,
}

impl NativeConnector {
    /// Creates a connector without a revocation verifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks certificate TLS servers with `verifier` on each new connection.
    #[must_use]
    pub fn with_revocation_verifier(
        mut self,
        verifier: Arc<dyn crate::RevocationVerifier>,
    ) -> Self {
        self.revocation_verifier = Some(verifier);
        self
    }
}

impl std::fmt::Debug for NativeConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeConnector")
            .field("revocation_verifier", &self.revocation_verifier.is_some())
            .finish()
    }
}

#[async_trait]
impl EndpointConnector for NativeConnector {
    type Connection = TacacsClient;

    async fn connect(
        &self,
        endpoint: PreparedEndpoint,
        _operation: OperationKind,
    ) -> anyhow::Result<Arc<Self::Connection>> {
        let endpoint = match &self.revocation_verifier {
            Some(verifier) => endpoint.with_revocation_verifier(Arc::clone(verifier)),
            None => endpoint,
        };
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
