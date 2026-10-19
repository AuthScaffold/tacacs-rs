use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_protocol::exchange::accounting::AccountingExchange;
use tacacsrs_protocol::exchange::authentication::PapAuthenticationExchange;
use tacacsrs_protocol::exchange::authorization::AuthorizationExchange;
use tacacsrs_protocol::accounting::reply::AccountingReply;
use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::authentication::reply::AuthenticationReply;
use tacacsrs_protocol::authorization::reply::AuthorizationReply;
use tacacsrs_protocol::authorization::request::AuthorizationRequest;
use tacacsrs_networking::{PreparedEndpoint, TacacsClient};

use super::connection::UpstreamConnection;
#[cfg(test)]
use super::connection::UpstreamConnector;
use super::{OperationKind, UpstreamRequestError};
use crate::runtime::ProxyLoopGuard;

/// Production connector backed by [`tacacsrs_networking`].
///
/// Reuses the native transport context prepared before generation publication.
#[derive(Debug, Clone)]
pub(crate) struct NetworkUpstreamConnector {
    proxy_loop_guard: ProxyLoopGuard,
}

impl NetworkUpstreamConnector {
    pub(crate) const fn new(proxy_loop_guard: ProxyLoopGuard) -> Self {
        Self { proxy_loop_guard }
    }

    #[cfg(test)]
    pub(crate) fn erased(self) -> Arc<UpstreamConnector> {
        Arc::new(ErasedNetworkConnector(self))
    }
}

#[async_trait]
impl tacacsrs_networking::routed::EndpointConnector for NetworkUpstreamConnector {
    type Connection = TacacsUpstreamConnection;

    async fn retire(&self, connection: &Self::Connection) {
        connection.stop_accepting_new_sessions().await;
    }
    fn close(&self, connection: &Self::Connection) {
        connection.close();
    }
    async fn close_and_join(
        &self,
        connection: &Self::Connection,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        connection.close_and_join(deadline).await
    }

    async fn connect(
        &self,
        endpoint: PreparedEndpoint,
        operation: OperationKind,
    ) -> anyhow::Result<Arc<Self::Connection>> {
        let address = endpoint.address().to_string();
        let connection = TacacsClient::connect_prepared(
            endpoint.with_connection_guard(self.proxy_loop_guard.clone()),
        )
        .await?;

        Ok(Arc::new(TacacsUpstreamConnection {
            server_address: address,
            operation,
            connection,
        }))
    }
}

/// Wraps a configured network client for the service state machine.
///
/// The networking layer selects a dedicated connection or a shared
/// single-connection transport for each operation. The agent only runs
/// request/reply flows and controls failover.
pub(crate) struct TacacsUpstreamConnection {
    /// The `host:port` address of the TACACS+ server.
    server_address: String,
    /// Operation isolated on this adaptive client.
    operation: OperationKind,
    /// The adaptive client connection.
    connection: TacacsClient,
}

#[cfg(test)]
struct ErasedNetworkConnector(NetworkUpstreamConnector);

#[cfg(test)]
#[async_trait]
impl tacacsrs_networking::routed::EndpointConnector for ErasedNetworkConnector {
    type Connection = dyn UpstreamConnection;

    async fn retire(&self, connection: &Self::Connection) {
        connection.stop_accepting_new_sessions().await;
    }
    fn close(&self, connection: &Self::Connection) {
        connection.close();
    }
    async fn close_and_join(
        &self,
        connection: &Self::Connection,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        connection.close_and_join(deadline).await
    }

    async fn connect(
        &self,
        endpoint: PreparedEndpoint,
        operation: OperationKind,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        tacacsrs_networking::routed::EndpointConnector::connect(&self.0, endpoint, operation)
            .await
            .map(|connection| connection as Arc<dyn UpstreamConnection>)
    }
}

#[async_trait]
impl UpstreamConnection for TacacsUpstreamConnection {
    fn server_address(&self) -> &str {
        &self.server_address
    }

    async fn stop_accepting_new_sessions(&self) {
        self.connection.stop_accepting_new_sessions().await;
    }

    fn close(&self) {
        self.connection.close();
    }

    async fn close_and_join(
        &self,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.connection.close_and_join(deadline).await
    }

    async fn open_conversation(&self) -> anyhow::Result<tacacsrs_networking::ClientConversation> {
        self.connection
            .open_conversation()
            .await
            .with_context(|| format!("Failed to open a session on {}", self.server_address))
    }

    async fn send_accounting(
        &self,
        request: AccountingRequest,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<AccountingReply, UpstreamRequestError> {
        debug_assert_eq!(self.operation, OperationKind::Accounting);
        log_session_start(
            "accounting",
            &self.server_address,
            &format!("user={}, args={}", request.user, request.args.len()),
        );

        let response = self
            .connection
            .execute_classified_until(AccountingExchange::new(request), deadline)
            .await;

        match &response {
            Ok(resp) => {
                log_protocol_reply(
                    "Accounting",
                    &self.server_address,
                    &resp.status,
                    &resp.server_msg,
                );
            }
            Err(error) => {
                log_session_failure("Accounting", &self.server_address, error);
            }
        }

        response.map_err(|error| {
            UpstreamRequestError::from_fixed(
                error,
                shared_failure_context("accounting", &self.server_address),
            )
        })
    }

    async fn authenticate_pap(
        &self,
        exchange: PapAuthenticationExchange,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<AuthenticationReply, UpstreamRequestError> {
        debug_assert_eq!(self.operation, OperationKind::Authentication);
        self.connection
            .execute_classified_until(exchange, deadline)
            .await
            .map_err(|error| {
                UpstreamRequestError::from_fixed(
                    error,
                    shared_failure_context("PAP authentication", &self.server_address),
                )
            })
    }

    async fn send_authorization(
        &self,
        request: AuthorizationRequest,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<AuthorizationReply, UpstreamRequestError> {
        debug_assert_eq!(self.operation, OperationKind::Authorization);
        log_session_start(
            "authorization",
            &self.server_address,
            &format!("user={}, args={}", request.user, request.args.len()),
        );

        let response = self
            .connection
            .execute_classified_until(AuthorizationExchange::new(request), deadline)
            .await;

        match &response {
            Ok(resp) => {
                log_protocol_reply(
                    "Authorization",
                    &self.server_address,
                    &resp.status,
                    &resp.server_msg,
                );
            }
            Err(error) => {
                log_session_failure("Authorization", &self.server_address, error);
            }
        }

        response.map_err(|error| {
            UpstreamRequestError::from_fixed(
                error,
                shared_failure_context("authorization", &self.server_address),
            )
        })
    }
}

fn log_session_start(operation: &'static str, server_address: &str, summary: &str) {
    log::debug!("Starting a TACACS+ session on {server_address} for {operation} ({summary})");
}

fn log_protocol_reply<Status: std::fmt::Debug>(
    operation: &'static str,
    server_address: &str,
    status: &Status,
    server_msg: &str,
) {
    log::debug!(
        "{operation} reply from {server_address}: status={status:?}, server_msg={}",
        if server_msg.is_empty() {
            "(empty)"
        } else {
            server_msg
        },
    );
}

fn log_session_failure(
    operation: &'static str,
    server_address: &str,
    error: &tacacsrs_networking::FixedExchangeError,
) {
    log::warn!("{operation} request to {server_address} failed: {error:#}");
}

fn shared_failure_context(operation: &'static str, server_address: &str) -> String {
    format!("Failed to send an {operation} request to {server_address}")
}
