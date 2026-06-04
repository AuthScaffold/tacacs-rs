use std::sync::Arc;

use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse,
};
use tacacsrs_config::TacacsPlusServer;

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
/// The connector is called by [`ServiceState`](crate::service) whenever a
/// fresh upstream connection manager is needed, such as during startup warm-up
/// or after a previous operation failed.
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
