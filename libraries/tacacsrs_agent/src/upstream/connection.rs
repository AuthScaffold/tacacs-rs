use std::sync::Arc;

use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse,
};
use tacacsrs_config::TacacsPlusServer;
use tacacsrs_networking::ClientSession;

#[async_trait]
/// Abstracts a single persistent TACACS+ server connection used by the service.
///
/// This trait is the seam between the service's failover state machine and the
/// actual network I/O. Production code wraps a [`tacacsrs_networking::TacacsClient`];
/// tests inject fakes that simulate failures, single-session servers, and
/// connection delays.
pub(crate) trait UpstreamConnection: Send + Sync {
    /// Returns the `host:port` address string for this upstream server.
    fn server_address(&self) -> &str;

    /// Stops this cached connection from accepting new TACACS+ sessions.
    ///
    /// Existing sessions that have already been created are allowed to drain
    /// through the networking runtime. The service calls this when a datastore
    /// reload removes or replaces a server definition.
    async fn stop_accepting_new_sessions(&self);

    /// Creates a raw TACACS+ packet session against this upstream server.
    ///
    /// The caller is responsible for sending and receiving TACACS+ packets over
    /// the returned session and marking it complete when proxying finishes.
    ///
    /// # Errors
    ///
    /// Returns an error if a new upstream session cannot be created.
    async fn create_raw_session(&self) -> anyhow::Result<ClientSession>;

    /// Sends one accounting request and returns the server's reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be created or the accounting
    /// exchange fails at the TACACS+ protocol level.
    async fn send_accounting(
        &self,
        request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse>;

    /// Sends one authorization request and returns the server's reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be created or the authorization
    /// exchange fails at the TACACS+ protocol level.
    async fn send_authorization(
        &self,
        request: &AuthorizationOperation,
    ) -> anyhow::Result<AuthorizationOperationResponse>;
}

#[async_trait]
/// Creates upstream connections for a configured TACACS+ server.
///
/// The connector is called by [`RoutingState`](crate::routing::RoutingState)
/// whenever a fresh upstream connection manager is needed, such as during
/// startup warm-up or after a previous operation failed.
pub(crate) trait UpstreamConnector: Send + Sync {
    /// Establishes a new upstream connection manager for the given TACACS+ server.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, TLS handshake, or TACACS+
    /// connection setup fails.
    async fn connect(
        &self,
        server: &TacacsPlusServer,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>>;
}
