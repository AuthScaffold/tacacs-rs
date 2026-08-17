use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_flows::accounting::AccountingExchange;
use tacacsrs_flows::authentication::PapAuthenticationExchange;
use tacacsrs_flows::authorization::AuthorizationExchange;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::authentication::reply::AuthenticationReply;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::authorization::request::AuthorizationRequest;
use tacacsrs_networking::{ConnectOptions, ConnectPreflight, TacacsClient};

use super::connection::{UpstreamConnection, UpstreamConnector};

/// Production connector backed by [`tacacsrs_networking`].
///
/// Reads the connection parameters from
/// [`tacacsrs_config::TacacsPlusServer`] for each connection attempt.
#[derive(Debug, Clone)]
pub(crate) struct NetworkUpstreamConnector {
    /// Disables TLS certificate verification for server connections.
    ///
    /// This option is dangerous. Use it only for development and tests.
    pub disable_certificate_verification: bool,
}

#[async_trait]
impl UpstreamConnector for NetworkUpstreamConnector {
    async fn connect(
        &self,
        server: Arc<TacacsPlusServer>,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let address = server.socket_address();
        let options = ConnectOptions::default()
            .with_certificate_verification_disabled(self.disable_certificate_verification)
            .with_timeout(server.timeout_duration())
            .with_preflight(ConnectPreflight::AccountingWatchdog);
        let connection = TacacsClient::connect_shared(server, options).await?;

        Ok(Arc::new(TacacsUpstreamConnection {
            server_address: address,
            connection,
        }))
    }
}

/// Wraps a configured network client for the service state machine.
///
/// The networking layer selects a dedicated connection or a shared
/// single-connection transport for each operation. The agent only runs
/// request/reply flows and controls failover.
struct TacacsUpstreamConnection {
    /// The `host:port` address of the TACACS+ server.
    server_address: String,
    /// The adaptive client connection.
    connection: TacacsClient,
}

#[async_trait]
impl UpstreamConnection for TacacsUpstreamConnection {
    fn server_address(&self) -> &str {
        &self.server_address
    }

    async fn stop_accepting_new_sessions(&self) {
        self.connection.stop_accepting_new_sessions().await;
    }

    async fn open_conversation(&self) -> anyhow::Result<tacacsrs_networking::ClientConversation> {
        self.connection
            .open_conversation()
            .await
            .with_context(|| format!("Failed to open a session on {}", self.server_address))
    }

    async fn send_accounting(&self, request: AccountingRequest) -> anyhow::Result<AccountingReply> {
        log_session_start(
            "accounting",
            &self.server_address,
            &format!("user={}, args={}", request.user, request.args.len()),
        );

        let response = self
            .connection
            .execute(AccountingExchange::new(request))
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

        response.with_context(|| shared_failure_context("accounting", &self.server_address))
    }

    async fn authenticate_pap(
        &self,
        exchange: PapAuthenticationExchange,
    ) -> anyhow::Result<AuthenticationReply> {
        self.connection
            .execute(exchange)
            .await
            .with_context(|| shared_failure_context("PAP authentication", &self.server_address))
    }

    async fn send_authorization(
        &self,
        request: AuthorizationRequest,
    ) -> anyhow::Result<AuthorizationReply> {
        log_session_start(
            "authorization",
            &self.server_address,
            &format!("user={}, args={}", request.user, request.args.len()),
        );

        let response = self
            .connection
            .execute(AuthorizationExchange::new(request))
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

        response.with_context(|| shared_failure_context("authorization", &self.server_address))
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

fn log_session_failure(operation: &'static str, server_address: &str, error: &anyhow::Error) {
    log::warn!("{operation} request to {server_address} failed: {error:#}");
}

fn shared_failure_context(operation: &'static str, server_address: &str) -> String {
    format!("Failed to send an {operation} request to {server_address}")
}
