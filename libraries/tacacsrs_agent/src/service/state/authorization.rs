//! Authorization request execution for [`ServiceState`].

use std::sync::atomic::Ordering;

use tacacsrs_agent_client::{AuthorizationOperation, AuthorizationOperationResponse, ServiceError};
use tacacsrs_config::TacacsPlusServerExt;

use super::ServiceState;

impl ServiceState {
    /// Executes one IPC authorization RPC against the currently selected
    /// upstream TACACS+ server.
    ///
    /// Authorization follows the same connection strategy and failover model as
    /// accounting: dedicated one-shot connections are used until a server proves
    /// single-connection support, after which requests reuse the cached shared
    /// connection.
    pub(in crate::service) async fn execute_authorization_request(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        let _client_guard = self.client_tracker.start_guard();
        let active_index = *self.active_index.read().await;

        if self.servers[active_index]
            .single_connection_supported
            .load(Ordering::Relaxed)
        {
            return self
                .execute_authorization_on_shared_connection(&request)
                .await;
        }

        self.execute_authorization_with_dedicated_connection(active_index, &request)
            .await
    }

    /// Executes an authorization request over the shared cached connection
    /// (single-connection mode).
    async fn execute_authorization_on_shared_connection(
        &self,
        request: &AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        let bound_server = self.bind_server_for_new_session().await.map_err(|error| {
            log::warn!("Failed to bind IPC request to an upstream server: {error:#}");
            ServiceError::new(error.to_string()).retriable(true)
        })?;

        log::debug!(
            "Executing authorization request via {} (server index {}, shared connection)",
            bound_server.connection.server_address(),
            bound_server.index,
        );

        match bound_server.connection.send_authorization(request).await {
            Ok(response) => {
                self.check_single_connection_negotiation(
                    bound_server.index,
                    &*bound_server.connection,
                )
                .await;
                Ok(response)
            }
            Err(error) => {
                if !bound_server.connection.is_usable_for_new_sessions().await {
                    log::info!(
                        "Shared connection to {} no longer usable; \
                         falling back to a dedicated connection",
                        self.servers[bound_server.index].server.socket_address(),
                    );
                    self.check_single_connection_negotiation(
                        bound_server.index,
                        &*bound_server.connection,
                    )
                    .await;
                    return self
                        .execute_authorization_with_dedicated_connection(
                            bound_server.index,
                            request,
                        )
                        .await;
                }

                log::warn!(
                    "Authorization request failed on {}: {error:#}",
                    bound_server.connection.server_address(),
                );
                self.note_failure(bound_server.index).await;
                Err(ServiceError::new(error.to_string())
                    .with_server(bound_server.connection.server_address())
                    .retriable(true))
            }
        }
    }

    /// Sends a single authorization request over a dedicated one-shot TCP
    /// connection (no background tasks, no session multiplexing).
    async fn execute_authorization_with_dedicated_connection(
        &self,
        index: usize,
        request: &AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        let address = self.servers[index].server.socket_address();
        log::debug!("Sending dedicated authorization request to {address}");

        match self
            .connector
            .send_authorization_dedicated(&self.servers[index].server, request)
            .await
        {
            Ok(result) => {
                self.note_dedicated_single_connect_result(
                    index,
                    &address,
                    result.single_connect_supported,
                );
                Ok(result.response)
            }
            Err(error) => {
                log::warn!("Dedicated authorization request to {address} failed: {error:#}");
                self.note_failure(index).await;
                Err(ServiceError::new(error.to_string())
                    .with_server(&address)
                    .retriable(true))
            }
        }
    }
}
