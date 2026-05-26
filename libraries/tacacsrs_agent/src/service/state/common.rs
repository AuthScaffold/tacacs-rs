//! Shared operation helpers for [`ServiceState`].

use std::sync::atomic::Ordering;

use async_trait::async_trait;
use tacacsrs_agent_client::ServiceError;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_networking::SingleConnectionState;

use super::ServiceState;
use crate::upstream::{DedicatedOperationResult, UpstreamConnection, UpstreamConnector};

/// Operation-specific hooks used by the shared TACACS+ routing state machine.
///
/// Accounting and authorization differ in request/response types and upstream
/// send methods, but they share the same client tracking, active-server
/// selection, single-connection upgrade/downgrade, dedicated fallback, and
/// failover behavior. Implementing this trait keeps those specializations
/// small while preserving typed request and response values.
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

    /// Sends the operation over a cached shared upstream connection.
    async fn send_shared(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> anyhow::Result<Self::Response>;

    /// Sends the operation over a dedicated one-shot upstream connection.
    async fn send_dedicated(
        connector: &dyn UpstreamConnector,
        server: &TacacsPlusServer,
        request: &Self::Request,
    ) -> anyhow::Result<DedicatedOperationResult<Self::Response>>;
}

impl ServiceState {
    /// Executes one IPC operation against the currently selected upstream
    /// TACACS+ server.
    ///
    /// Dedicated one-shot connections are used until the server proves
    /// single-connection support, after which future requests reuse the cached
    /// shared connection. If a shared connection becomes unusable mid-request,
    /// the same operation is retried over a dedicated connection before the
    /// server is treated as failed.
    pub(in crate::service::state) async fn execute_operation<Operation>(
        &self,
        request: Operation::Request,
    ) -> Result<Operation::Response, ServiceError>
    where
        Operation: RoutedOperation,
    {
        let _client_guard = self.client_tracker.start_guard();
        let active_index = *self.active_index.read().await;

        if self.servers[active_index]
            .single_connection_supported
            .load(Ordering::Relaxed)
        {
            return self
                .execute_operation_on_shared_connection::<Operation>(&request)
                .await;
        }

        self.execute_operation_with_dedicated_connection::<Operation>(active_index, &request)
            .await
    }

    async fn execute_operation_on_shared_connection<Operation>(
        &self,
        request: &Operation::Request,
    ) -> Result<Operation::Response, ServiceError>
    where
        Operation: RoutedOperation,
    {
        let bound_server = self.bind_server_for_new_session().await.map_err(|error| {
            log::warn!("Failed to bind IPC request to an upstream server: {error:#}");
            ServiceError::new(error.to_string()).retriable(true)
        })?;

        log::debug!(
            "Executing {} request via {} (server index {}, shared connection)",
            Operation::NAME,
            bound_server.connection.server_address(),
            bound_server.index,
        );

        match Operation::send_shared(&*bound_server.connection, request).await {
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
                        .execute_operation_with_dedicated_connection::<Operation>(
                            bound_server.index,
                            request,
                        )
                        .await;
                }

                log::warn!(
                    "{} request failed on {}: {error:#}",
                    Operation::DISPLAY_NAME,
                    bound_server.connection.server_address(),
                );
                self.note_failure(bound_server.index).await;
                Err(ServiceError::new(error.to_string())
                    .with_server(bound_server.connection.server_address())
                    .retriable(true))
            }
        }
    }

    async fn execute_operation_with_dedicated_connection<Operation>(
        &self,
        index: usize,
        request: &Operation::Request,
    ) -> Result<Operation::Response, ServiceError>
    where
        Operation: RoutedOperation,
    {
        let address = self.servers[index].server.socket_address();
        log::debug!("Sending dedicated {} request to {address}", Operation::NAME);

        match Operation::send_dedicated(&*self.connector, &self.servers[index].server, request)
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
                log::warn!("Dedicated {} request to {address} failed: {error:#}", Operation::NAME);
                self.note_failure(index).await;
                Err(ServiceError::new(error.to_string())
                    .with_server(&address)
                    .retriable(true))
            }
        }
    }

    pub(in crate::service::state) fn note_dedicated_single_connect_result(
        &self,
        index: usize,
        address: &str,
        single_connect_supported: bool,
    ) {
        if single_connect_supported
            && !self.servers[index]
                .single_connection_supported
                .swap(true, Ordering::Relaxed)
        {
            log::info!(
                "Server {address} supports single-connection mode; \
                 switching to shared connections for future requests",
            );
        }
    }

    /// Inspects the single-connection negotiation result on `connection` and
    /// updates the per-server flag in either direction.
    ///
    /// - [`Supported`](SingleConnectionState::Supported) → enables the shared
    ///   cached-connection path for future requests.
    /// - [`NotSupported`](SingleConnectionState::NotSupported) → reverts to
    ///   dedicated per-request connections (e.g. the server withdrew support
    ///   for traffic-shifting).
    /// - `Initial` / `Negotiating` — no actionable information yet.
    pub(in crate::service::state) async fn check_single_connection_negotiation(
        &self,
        index: usize,
        connection: &dyn UpstreamConnection,
    ) {
        match connection.single_connection_state().await {
            SingleConnectionState::Supported
                if !self.servers[index]
                    .single_connection_supported
                    .swap(true, Ordering::Relaxed) =>
            {
                log::info!(
                    "Server {} supports single-connection mode; \
                         switching to shared connections for future requests",
                    self.servers[index].server.socket_address(),
                );
            }
            SingleConnectionState::NotSupported
                if self.servers[index]
                    .single_connection_supported
                    .swap(false, Ordering::Relaxed) =>
            {
                log::info!(
                    "Server {} revoked single-connection support; \
                         switching to dedicated connections for future requests",
                    self.servers[index].server.socket_address(),
                );
            }
            // Initial or Negotiating — no actionable information yet.
            _ => {}
        }
    }
}
