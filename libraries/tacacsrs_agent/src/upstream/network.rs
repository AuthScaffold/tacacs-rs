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
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_networking::config_connect::{self, ConnectOptions};
use tacacsrs_networking::connection::TacacsConnection;
use tacacsrs_networking::dedicated_connection::DedicatedConnection;
use tacacsrs_networking::traits::SessionManagementTrait;
use tacacsrs_networking::{ExchangeResult, SingleConnectionState};

use super::mapping::{
    build_accounting_request, build_authorization_request, to_accounting_response,
    to_authorization_response,
};
use super::traits::{DedicatedOperationResult, UpstreamConnection, UpstreamConnector};

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
        let connection = connect_upstream(server, self.disable_certificate_verification).await?;
        Ok(Arc::new(TacacsUpstreamConnection {
            server_address: address,
            connection,
        }))
    }

    async fn send_accounting_dedicated(
        &self,
        server: &TacacsPlusServer,
        request: &AccountingOperation,
    ) -> anyhow::Result<DedicatedOperationResult<AccountingOperationResponse>> {
        send_dedicated_accounting(server, self.disable_certificate_verification, request).await
    }

    async fn send_authorization_dedicated(
        &self,
        server: &TacacsPlusServer,
        request: &AuthorizationOperation,
    ) -> anyhow::Result<DedicatedOperationResult<AuthorizationOperationResponse>> {
        send_dedicated_authorization(server, self.disable_certificate_verification, request).await
    }
}

/// Wraps a persistent [`TacacsConnection`] for use by the service state machine.
///
/// Each instance represents one open TCP/TLS connection to a single upstream
/// TACACS+ server. It is stored in the per-server connection cache and shared
/// across concurrent IPC handlers via `Arc`.
struct TacacsUpstreamConnection {
    /// The `host:port` of the upstream server this connection targets.
    server_address: String,
    /// The underlying multiplexed TACACS+ connection.
    connection: Arc<TacacsConnection>,
}

#[async_trait]
impl UpstreamConnection for TacacsUpstreamConnection {
    fn server_address(&self) -> &str {
        &self.server_address
    }

    async fn is_usable_for_new_sessions(&self) -> bool {
        self.connection.can_create_sessions().await
    }

    async fn single_connection_state(&self) -> SingleConnectionState {
        self.connection.single_connection_state().await
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

        let session = create_session(&self.connection, &self.server_address).await?;

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

        let session = create_session(&self.connection, &self.server_address).await?;

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

fn log_session_start(operation: &'static str, server_address: &str, summary: &str) {
    log::debug!("Creating TACACS+ session on {server_address} for {operation} request ({summary})");
}

async fn create_session(
    connection: &Arc<TacacsConnection>,
    server_address: &str,
) -> anyhow::Result<tacacsrs_networking::session::Session> {
    connection
        .create_session()
        .await
        .with_context(|| format!("Failed to create session on {server_address}"))
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

/// Establishes a new TCP (or TLS/PSK) connection to an upstream TACACS+ server.
///
/// The connection sequence is:
/// 1. Open a TCP stream with the configured connect timeout.
/// 2. If TLS/PSK is configured, negotiate the appropriate handshake.
/// 3. Start the TACACS+ connection handler on the resulting stream.
///
/// # Errors
///
/// Returns an error if TCP connection times out, TLS negotiation fails, or
/// the TACACS+ connection handler cannot start.
async fn connect_upstream(
    server: &TacacsPlusServer,
    disable_certificate_verification: bool,
) -> anyhow::Result<Arc<TacacsConnection>> {
    let address = server.socket_address();
    let timeout_duration = server.timeout_duration();

    let security_label = security_label(server);
    log::debug!(
        "Connecting to upstream TACACS+ server {address} (security: {security_label}, timeout: {timeout_duration:?})",
    );

    let options = ConnectOptions {
        disable_certificate_verification,
        timeout: Some(timeout_duration),
    };

    let stream = config_connect::establish_stream(server, &options)
        .await
        .with_context(|| {
            log::warn!("Connection to {address} failed");
            format!("Failed to connect to {address}")
        })?;

    let obfuscation_key = if server.is_tls() {
        None
    } else {
        server.obfuscation_key()
    };
    let connection = Arc::new(TacacsConnection::new(obfuscation_key.as_deref()));

    connection
        .run(stream)
        .await
        .inspect_err(|e| {
            log::warn!("Connection handler start for {address} failed: {e:#}");
        })
        .context("Failed to start connection handler")?;

    log::debug!(
        "{} connection to {address} ready",
        if server.is_tls() {
            "TLS"
        } else {
            "TCP"
        },
    );

    Ok(connection)
}

/// Sends a single accounting request over a dedicated connection.
async fn send_dedicated_accounting(
    server: &TacacsPlusServer,
    disable_certificate_verification: bool,
    request: &AccountingOperation,
) -> anyhow::Result<DedicatedOperationResult<AccountingOperationResponse>> {
    let tacacs_request = build_accounting_request(request);
    send_dedicated_exchange(
        server,
        disable_certificate_verification,
        "accounting",
        |mut conn| async move {
            conn.send_accounting(tacacs_request, TacacsFlags::empty())
                .await
        },
        |address, reply| Ok(to_accounting_response(address, reply)),
    )
    .await
}

/// Sends a single authorization request over a dedicated connection.
async fn send_dedicated_authorization(
    server: &TacacsPlusServer,
    disable_certificate_verification: bool,
    request: &AuthorizationOperation,
) -> anyhow::Result<DedicatedOperationResult<AuthorizationOperationResponse>> {
    let tacacs_request = build_authorization_request(request)?;
    send_dedicated_exchange(
        server,
        disable_certificate_verification,
        "authorization",
        |mut conn| async move {
            conn.send_authorization(tacacs_request, TacacsFlags::empty())
                .await
        },
        to_authorization_response,
    )
    .await
}

type BoxedDedicatedConnection = DedicatedConnection<
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
>;

async fn send_dedicated_exchange<WireReply, Response, SendExchange, SendFuture, MapResponse>(
    server: &TacacsPlusServer,
    disable_certificate_verification: bool,
    operation: &'static str,
    send_exchange: SendExchange,
    map_response: MapResponse,
) -> anyhow::Result<DedicatedOperationResult<Response>>
where
    SendExchange: FnOnce(BoxedDedicatedConnection) -> SendFuture,
    SendFuture: std::future::Future<Output = anyhow::Result<ExchangeResult<WireReply>>>,
    MapResponse: FnOnce(&str, WireReply) -> anyhow::Result<Response>,
{
    let address = server.socket_address();
    let timeout_duration = server.timeout_duration();

    let security_label = security_label(server);
    log::debug!(
        "Dedicated {operation} request to {address} (security: {security_label}, timeout: {timeout_duration:?})",
    );

    let options = ConnectOptions {
        disable_certificate_verification,
        timeout: Some(timeout_duration),
    };

    let stream = config_connect::establish_stream(server, &options)
        .await
        .with_context(|| format!("Failed to connect to {address}"))?;

    let obfuscation_key = server.obfuscation_key();
    let conn = DedicatedConnection::new(stream, obfuscation_key.as_deref());
    let exchange = send_exchange(conn).await?;
    let single_connect_supported = exchange.single_connect_supported;
    let response = map_response(&address, exchange.reply)?;

    log::debug!(
        "Dedicated {operation} response from {address}: single_connect={single_connect_supported}",
    );

    Ok(DedicatedOperationResult {
        response,
        single_connect_supported,
    })
}

fn security_label(server: &TacacsPlusServer) -> &'static str {
    if server.is_tls() {
        "tls"
    } else if server.is_obfuscation() {
        "obfuscation"
    } else {
        "plain-tcp"
    }
}
