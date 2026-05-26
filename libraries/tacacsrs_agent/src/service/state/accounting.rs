//! Accounting request execution for [`ServiceState`].

use std::sync::atomic::Ordering;

use tacacsrs_agent_client::{AccountingOperation, AccountingOperationResponse, ServiceError};
use tacacsrs_config::TacacsPlusServerExt;

use super::ServiceState;

impl ServiceState {
    /// Executes one IPC accounting RPC against the currently selected upstream
    /// TACACS+ server.
    ///
    /// # Connection strategy
    ///
    /// By default every request gets its own dedicated short-lived TCP
    /// connection (the safe path for servers that do not support
    /// single-connection mode).
    ///
    /// Once a server proves it supports single-connection mode
    /// ([`SingleConnectionState::Supported`]), future requests multiplex
    /// sessions over a shared cached connection.  The server may later
    /// withdraw that support (e.g. for traffic-shifting), in which case the
    /// service reverts to dedicated connections.
    pub(in crate::service) async fn execute_accounting_request(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        let _client_guard = self.client_tracker.start_guard();
        let active_index = *self.active_index.read().await;

        // When the server has proven single-connection support, reuse the
        // shared cached connection for session multiplexing.
        if self.servers[active_index]
            .single_connection_supported
            .load(Ordering::Relaxed)
        {
            return self.execute_on_shared_connection(&request).await;
        }

        // Default path: one dedicated TCP connection per request.
        self.execute_with_dedicated_connection(active_index, &request)
            .await
    }

    /// Executes a request over the shared cached connection (single-connection
    /// mode).
    ///
    /// If the cached connection becomes unusable mid-request (e.g. the server
    /// revoked single-connection support), the request is transparently
    /// retried on a fresh dedicated connection.
    async fn execute_on_shared_connection(
        &self,
        request: &AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        let bound_server = self.bind_server_for_new_session().await.map_err(|error| {
            log::warn!("Failed to bind IPC request to an upstream server: {error:#}");
            ServiceError::new(error.to_string()).retriable(true)
        })?;

        log::debug!(
            "Executing accounting request via {} (server index {}, shared connection)",
            bound_server.connection.server_address(),
            bound_server.index,
        );

        match bound_server.connection.send_accounting(request).await {
            Ok(response) => {
                self.check_single_connection_negotiation(
                    bound_server.index,
                    &*bound_server.connection,
                )
                .await;
                Ok(response)
            }
            Err(error) => {
                // If the connection is no longer usable for new sessions the
                // failure is a local connection-capacity issue (the server may
                // have revoked single-connection support), not a remote server
                // outage.  Fall back to a dedicated connection.
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
                        .execute_with_dedicated_connection(bound_server.index, request)
                        .await;
                }

                log::warn!(
                    "Accounting request failed on {}: {error:#}",
                    bound_server.connection.server_address(),
                );
                self.note_failure(bound_server.index).await;
                Err(ServiceError::new(error.to_string())
                    .with_server(bound_server.connection.server_address())
                    .retriable(true))
            }
        }
    }

    /// Sends a single accounting request over a dedicated one-shot TCP
    /// connection (no background tasks, no session multiplexing).
    ///
    /// This is the default path.  Each IPC request gets its own short-lived
    /// upstream TCP connection, which is discarded after the response.
    /// The outgoing packet includes the single-connect flag so the server's
    /// response reveals whether it supports multiplexing; if it does, the
    /// per-server flag is set so future requests upgrade to the shared
    /// cached-connection path.
    async fn execute_with_dedicated_connection(
        &self,
        index: usize,
        request: &AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        let address = self.servers[index].server.socket_address();
        log::debug!("Sending dedicated accounting request to {address}");

        match self
            .connector
            .send_accounting_dedicated(&self.servers[index].server, request)
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
                log::warn!("Dedicated accounting request to {address} failed: {error:#}");
                self.note_failure(index).await;
                Err(ServiceError::new(error.to_string())
                    .with_server(&address)
                    .retriable(true))
            }
        }
    }
}
