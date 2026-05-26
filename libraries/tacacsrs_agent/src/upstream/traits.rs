use std::sync::Arc;

use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse,
};
use tacacsrs_config::TacacsPlusServer;
use tacacsrs_networking::SingleConnectionState;

#[async_trait]
/// Abstracts a single persistent TACACS+ server connection used by the service.
///
/// This trait is the seam between the service's failover state machine and the
/// actual network I/O. Production code wraps a [`tacacsrs_networking::TacacsConnection`];
/// tests inject fakes that simulate failures, single-session servers, and
/// connection delays.
pub(crate) trait UpstreamConnection: Send + Sync {
    /// Returns the `host:port` address string for this upstream server.
    fn server_address(&self) -> &str;

    /// Returns `true` if this connection can still accept new TACACS+ sessions.
    ///
    /// Connections may become unusable when:
    /// - The server does not support single-connection multiplexing.
    /// - The server has sent a graceful-shutdown notification.
    /// - A previous session encountered an unrecoverable transport error.
    async fn is_usable_for_new_sessions(&self) -> bool;

    /// Returns the TACACS+ single-connection negotiation state.
    ///
    /// The state indicates whether the server supports multiplexing multiple
    /// sessions over one connection.  The service uses `NotSupported` to
    /// permanently switch a server to dedicated per-request connections.
    async fn single_connection_state(&self) -> SingleConnectionState;

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
/// fresh upstream connection is needed: during startup warm-up, when a cached
/// connection is no longer usable, or when an operation must use a dedicated
/// one-shot connection.
pub(crate) trait UpstreamConnector: Send + Sync {
    /// Establishes a new reusable connection to the given TACACS+ server.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, TLS handshake, or TACACS+
    /// connection setup fails.
    async fn connect(
        &self,
        server: &TacacsPlusServer,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>>;

    /// Sends a single accounting request over a dedicated one-shot connection.
    ///
    /// Opens a connection, sends one TACACS+ packet, reads one response, and
    /// closes the connection. The outgoing packet includes the single-connect
    /// flag so the server's response reveals whether it supports multiplexing.
    async fn send_accounting_dedicated(
        &self,
        server: &TacacsPlusServer,
        request: &AccountingOperation,
    ) -> anyhow::Result<DedicatedOperationResult<AccountingOperationResponse>>;

    /// Sends a single authorization request over a dedicated one-shot connection.
    ///
    /// Opens a connection, sends one TACACS+ packet, reads one response, and
    /// closes the connection. The outgoing packet includes the single-connect
    /// flag so the server's response reveals whether it supports multiplexing.
    async fn send_authorization_dedicated(
        &self,
        server: &TacacsPlusServer,
        request: &AuthorizationOperation,
    ) -> anyhow::Result<DedicatedOperationResult<AuthorizationOperationResponse>>;
}

/// Result of a one-shot request sent through a dedicated connection.
pub(crate) struct DedicatedOperationResult<Response> {
    /// The operation response mapped to domain types.
    pub response: Response,
    /// Whether the server indicated support for single-connection mode.
    pub single_connect_supported: bool,
}
