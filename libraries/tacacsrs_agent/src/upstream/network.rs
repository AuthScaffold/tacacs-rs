use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse,
};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_flows::accounting::AccountingFlow;
use tacacsrs_flows::authorization::AuthorizationFlow;
use tacacsrs_networking::{ConnectOptions, ConnectPreflight, TacacsClient};

use super::mapping::{
    build_accounting_request, build_authorization_request, to_accounting_response,
    to_authorization_response,
};
use super::traits::{UpstreamConnection, UpstreamConnector};

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

    async fn send_accounting(
        &self,
        request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        log_session_start(
            "accounting",
            &self.server_address,
            &format!("user={}, cmd={}", request.user, request.command),
        );

        let session = self.create_session().await?;
        let response = session
            .send_accounting_request(build_accounting_request(request))
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

        let response =
            response.with_context(|| shared_failure_context("accounting", &self.server_address))?;

        Ok(to_accounting_response(&self.server_address, response))
    }

    async fn send_authorization(
        &self,
        request: &AuthorizationOperation,
    ) -> anyhow::Result<AuthorizationOperationResponse> {
        log_session_start(
            "authorization",
            &self.server_address,
            &format!(
                "user={}, service={}, cmd={}",
                request.user,
                request.service().unwrap_or("<missing>"),
                request.command().unwrap_or("<missing>"),
            ),
        );

        let session = self.create_session().await?;
        let response = session
            .send_authorization_request(build_authorization_request(request)?)
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

        let response = response
            .with_context(|| shared_failure_context("authorization", &self.server_address))?;

        to_authorization_response(&self.server_address, response)
    }
}

impl TacacsUpstreamConnection {
    async fn create_session(&self) -> anyhow::Result<tacacsrs_networking::ClientSession> {
        self.connection
            .create_session()
            .await
            .with_context(|| format!("Failed to create session on {}", self.server_address))
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
