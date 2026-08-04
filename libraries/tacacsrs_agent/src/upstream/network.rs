use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_flows::accounting::AccountingExchange;
use tacacsrs_flows::authorization::AuthorizationExchange;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::authorization::request::AuthorizationRequest;
use tacacsrs_networking::{ConnectOptions, ConnectPreflight, TacacsClient};

use super::connection::{UpstreamConnection, UpstreamConnector};

/// Production connector backed by [`tacacsrs_networking`].
///
/// Extracts per-server connection parameters from the provided
/// [`tacacsrs_config::TacacsPlusServer`] at each connection attempt.
#[derive(Debug, Clone)]
pub(crate) struct NetworkUpstreamConnector {
    /// Dangerously disable TLS certificate verification for upstream connections.
    pub disable_certificate_verification: bool,
}

#[async_trait]
impl UpstreamConnector for NetworkUpstreamConnector {
    async fn connect(
        &self,
        server: &TacacsPlusServer,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let address = server.socket_address();
        let options = ConnectOptions::default()
            .with_certificate_verification_disabled(self.disable_certificate_verification)
            .with_timeout(server.timeout_duration())
            .with_preflight(ConnectPreflight::AccountingWatchdog);
        let connection = TacacsClient::connect(server.clone(), options).await?;

        Ok(Arc::new(TacacsUpstreamConnection {
            server_address: address,
            connection,
        }))
    }
}

/// Wraps a configured networking client connection for use by the service state
/// machine.
///
/// The networking layer owns whether each operation uses a dedicated stream or
/// an upgraded single-connection stream. The agent sees only request/reply flow
/// execution and failover across configured servers.
struct TacacsUpstreamConnection {
    /// The `host:port` of the upstream server this connection targets.
    server_address: String,
    /// The underlying adaptive client connection.
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
            .with_context(|| format!("Failed to open conversation on {}", self.server_address))
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
    log::debug!("Creating TACACS+ session on {server_address} for {operation} request ({summary})");
}

fn log_protocol_reply<Status: std::fmt::Debug>(
    operation: &'static str,
    server_address: &str,
    status: &Status,
    server_msg: &str,
) {
    log::debug!(
        "{operation} response from {server_address}: status={status:?}, server_msg={}",
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
    format!("Failed to send {operation} request via {server_address}")
}
