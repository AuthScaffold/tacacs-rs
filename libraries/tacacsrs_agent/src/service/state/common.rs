//! Shared operation helpers for [`ServiceState`].

use async_trait::async_trait;
use tacacsrs_agent_client::ServiceError;

use super::ServiceState;
use crate::upstream::UpstreamConnection;

/// Operation-specific hooks used by the shared TACACS+ routing state machine.
///
/// Accounting and authorization differ in request/response types and upstream
/// send methods, but they share the same client tracking, active-server
/// selection, failure recording, and failover behavior. Implementing this trait
/// keeps those specializations small while preserving typed request and response
/// values.
#[async_trait]
pub(in crate::service::state) trait RoutedOperation:
    Send + Sync + 'static
{
    /// IPC-level request type for the operation.
    type Request: Send + Sync;
    /// IPC-level response type for the operation.
    type Response: Send;

    /// Lowercase operation name for log messages.
    const NAME: &'static str;
    /// Display operation name for log messages.
    const DISPLAY_NAME: &'static str;

    /// Sends the operation through the selected upstream connection.
    async fn send(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> anyhow::Result<Self::Response>;
}

impl ServiceState {
    /// Executes one IPC operation against the currently selected upstream
    /// TACACS+ server.
    ///
    /// The networking layer owns dedicated versus single-connection behavior.
    /// `ServiceState` only selects a configured server, records failures, and
    /// advances failover state for subsequent IPC requests.
    pub(in crate::service::state) async fn execute_operation<Operation>(
        &self,
        request: Operation::Request,
    ) -> Result<Operation::Response, ServiceError>
    where
        Operation: RoutedOperation,
    {
        let _client_guard = self.client_tracker.start_guard();
        let bound_server = self.bind_server_for_new_session().await.map_err(|error| {
            log::warn!("Failed to bind IPC request to an upstream server: {error:#}");
            ServiceError::new(error.to_string()).retriable(true)
        })?;

        log::debug!(
            "Executing {} request via {} (server index {})",
            Operation::NAME,
            bound_server.connection.server_address(),
            bound_server.index,
        );

        match Operation::send(&*bound_server.connection, &request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                log::warn!(
                    "{} request failed on {}: {error:#}",
                    Operation::DISPLAY_NAME,
                    bound_server.connection.server_address(),
                );
                self.note_failure(&bound_server.server_set, bound_server.index)
                    .await;
                Err(ServiceError::new(error.to_string())
                    .with_server(bound_server.connection.server_address())
                    .retriable(true))
            }
        }
    }
}
