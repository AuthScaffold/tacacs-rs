use std::sync::Arc;

use async_trait::async_trait;
use tacacsrs_config::TacacsPlusServer;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::authentication::reply::AuthenticationReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::authorization::request::AuthorizationRequest;
use tacacsrs_networking::ClientConversation;
use tacacsrs_flows::authentication::PapAuthenticationExchange;

use super::OperationKind;
use super::UpstreamRequestError;

#[async_trait]
/// Provides one persistent connection to a TACACS+ server.
///
/// This trait separates the service failover state from network I/O. Production
/// code wraps a [`tacacsrs_networking::TacacsClient`]. Tests use fakes to
/// simulate failures, servers that permit one session, and connection delays.
pub(crate) trait UpstreamConnection: Send + Sync {
    /// Returns the `host:port` address string for this upstream server.
    fn server_address(&self) -> &str;

    /// Stops this cached connection from accepting new TACACS+ sessions.
    ///
    /// Existing sessions can finish through the networking runtime. The service
    /// calls this method when a datastore reload removes or replaces a server.
    async fn stop_accepting_new_sessions(&self);

    /// Creates a raw TACACS+ packet session against this upstream server.
    ///
    /// The caller sends and receives TACACS+ packets through the returned
    /// session. The caller marks the session complete when proxying stops.
    ///
    /// # Errors
    ///
    /// Returns an error if a new upstream session cannot be created.
    async fn open_conversation(&self) -> anyhow::Result<ClientConversation>;

    /// Sends one accounting request and returns the server's reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be created or the accounting
    /// exchange fails at the TACACS+ protocol level.
    async fn send_accounting(
        &self,
        request: AccountingRequest,
    ) -> Result<AccountingReply, UpstreamRequestError>;

    /// Runs one fixed PAP authentication exchange.
    async fn authenticate_pap(
        &self,
        exchange: PapAuthenticationExchange,
    ) -> Result<AuthenticationReply, UpstreamRequestError>;

    /// Sends one authorization request and returns the server's reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be created or the authorization
    /// exchange fails at the TACACS+ protocol level.
    async fn send_authorization(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationReply, UpstreamRequestError>;
}

#[async_trait]
/// Creates connections to a configured TACACS+ server.
///
/// [`UpstreamManager`](crate::upstream::manager::UpstreamManager) calls the
/// connector when it needs a new connection. This occurs during startup warm-up
/// or after an operation fails.
pub(crate) trait UpstreamConnector: Send + Sync {
    /// Opens a new connection to the specified TACACS+ server.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, TLS handshake, or TACACS+
    /// connection setup fails.
    async fn connect(
        &self,
        server: Arc<TacacsPlusServer>,
        operation: OperationKind,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>>;
}
