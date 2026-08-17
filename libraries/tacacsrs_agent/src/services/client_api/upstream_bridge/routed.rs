//! Shared operation helpers for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_agent_client::ServiceError;

use super::UpstreamBridge;
use crate::upstream::UpstreamConnection;

/// Operation-specific hooks used by the client API upstream bridge.
///
/// Accounting and authorization have different request, reply, and send types.
/// They use the same server selection, failure recording, and failover behavior.
/// This trait keeps the operation-specific implementations small and typed.
#[async_trait]
pub(super) trait RoutedOperation: Send + Sync + 'static {
    /// Client API request type for the operation.
    type Request: Send;
    /// Client API response type for the operation.
    type Response: Send;

    /// Lowercase operation name for log messages.
    const NAME: &'static str;
    /// Operation name with display capitalization for log messages.
    const DISPLAY_NAME: &'static str;

    /// Sends the operation through the selected server connection.
    async fn send(
        connection: &dyn UpstreamConnection,
        request: Self::Request,
    ) -> anyhow::Result<Self::Response>;
}

impl UpstreamBridge {
    /// Runs one client API operation against the selected TACACS+ server.
    ///
    /// The networking layer selects dedicated or single-connection behavior.
    /// `UpstreamBridge` asks the upstream manager to select a server. It records
    /// failures and updates failover state for later client API requests.
    pub(super) async fn execute_operation<Operation>(
        &self,
        request: Operation::Request,
    ) -> Result<Operation::Response, ServiceError>
    where
        Operation: RoutedOperation,
    {
        let bound_server = self
            .upstream_manager
            .bind_server_for_new_session()
            .await
            .map_err(|error| {
                log::warn!("Failed to bind a client API request to a TACACS+ server: {error:#}");
                ServiceError::new(error.to_string()).retriable(true)
            })?;

        log::debug!(
            "Sending an {} request to {} (server index {})",
            Operation::NAME,
            bound_server.connection.server_address(),
            bound_server.index,
        );

        match Operation::send(&*bound_server.connection, request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                log::warn!(
                    "{} request failed on {}: {error:#}",
                    Operation::DISPLAY_NAME,
                    bound_server.connection.server_address(),
                );
                self.upstream_manager
                    .note_bound_server_failure(&bound_server)
                    .await;
                Err(ServiceError::new(error.to_string())
                    .with_server(bound_server.connection.server_address())
                    .retriable(true))
            }
        }
    }
}
