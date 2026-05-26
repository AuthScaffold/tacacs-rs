//! Persistent upstream TACACS+ connection management.
//!
//! This module adapts the lower-level networking/session APIs into the
//! service's higher-level operation model. Each upstream connection can be
//! reused for many IPC requests, while the service keeps ownership of failover
//! decisions and connection lifecycle.
//!
//! # Transport selection
//!
//! Each [`tacacsrs_config::TacacsPlusServer`] carries the YANG model fields that determine which transport is
//! used for the upstream TACACS+ connection:
//!
//! | Security | Transport |
//! |----------|-----------|
//! | `shared-secret` only | Plain TCP |
//! | no TLS fields and no `shared-secret` | Plain TCP without TACACS+ obfuscation |
//! | `client-identity` / `server-authentication` (certificate) | mTLS (X.509) |
//! | `client-identity` with `tls13-epsk` | TLS-PSK (feature-gated) |
//!
//! # Connection reuse
//!
//! Each upstream connection wraps a single persistent TCP/TLS connection
//! to one TACACS+ server. The TACACS+ protocol supports multiplexed sessions
//! over one connection when both sides negotiate single-connection mode. If
//! the server does not support reuse, the connection reports itself as
//! unusable for new sessions and the service reconnects for the next IPC
//! request.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_flows::accounting::AccountingFlow;
use tacacsrs_flows::authorization::AuthorizationFlow;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::authorization::request::AuthorizationRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType, TacacsAuthorizationStatus, TacacsFlags,
};
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus, AuthorizationArg,
    AuthorizationOperation, AuthorizationOperationResponse, AuthorizationResponseStatus,
};
use tacacsrs_networking::SingleConnectionState;
use tacacsrs_networking::config_connect::{self, ConnectOptions};
use tacacsrs_networking::connection::TacacsConnection;
use tacacsrs_networking::dedicated_connection::DedicatedConnection;
use tacacsrs_networking::traits::SessionManagementTrait;
use tacacsrs_networking::ExchangeResult;

#[async_trait]
/// Abstracts a single persistent TACACS+ server connection used by the service.
///
/// This trait is the seam between the service's failover state machine and the
/// actual network I/O. Production code uses [`TacacsUpstreamConnection`] which
/// wraps a [`TacacsConnection`]; tests inject fakes that simulate failures,
/// single-session servers, and connection delays.
pub(crate) trait UpstreamConnection: Send + Sync {
    /// Returns the `host:port` address string for this upstream server.
    fn server_address(&self) -> &str;

    /// Returns `true` if this connection can still accept new TACACS+ sessions.
    ///
    /// Connections may become unusable when:
    /// - The server does not support single-connection multiplexing.
    /// - The server has sent a graceful-shutdown notification.
    /// - A previous session encountered an unrecoverable transport error.
    async fn is_usable_for_new_sessions(&self) -> bool;

    /// Returns the TACACS+ single-connection negotiation state.
    ///
    /// The state indicates whether the server supports multiplexing multiple
    /// sessions over one connection.  The service uses `NotSupported` to
    /// permanently switch a server to dedicated per-request connections.
    async fn single_connection_state(&self) -> SingleConnectionState;

    /// Sends one accounting request and returns the server's reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be created or the accounting
    /// exchange fails at the TACACS+ protocol level.
    async fn send_accounting(
        &self,
        request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse>;

    /// Sends one authorization request and returns the server's reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the session cannot be created or the authorization
    /// exchange fails at the TACACS+ protocol level.
    async fn send_authorization(
        &self,
        request: &AuthorizationOperation,
    ) -> anyhow::Result<AuthorizationOperationResponse>;
}

#[async_trait]
/// Creates upstream connections for a configured TACACS+ server.
///
/// The connector is called by [`ServiceState`](crate::service) whenever a
/// fresh upstream connection is needed—either during startup warm-up or when
/// a cached connection is no longer usable.
pub(crate) trait UpstreamConnector: Send + Sync {
    /// Establishes a new connection to the given TACACS+ server.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, TLS handshake, or TACACS+
    /// connection setup fails.
    async fn connect(
        &self,
        server: &TacacsPlusServer,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>>;

    /// Sends a single accounting request over a dedicated one-shot connection.
    ///
    /// Opens a TCP connection, sends one TACACS+ packet, reads one response,
    /// and closes the connection.  No background tasks, no session
    /// multiplexing.  The outgoing packet includes the single-connect flag
    /// so the server's response reveals whether it supports multiplexing.
    async fn send_accounting_dedicated(
        &self,
        server: &TacacsPlusServer,
        request: &AccountingOperation,
    ) -> anyhow::Result<DedicatedOperationResult<AccountingOperationResponse>>;

    /// Sends a single authorization request over a dedicated one-shot connection.
    ///
    /// Opens a TCP connection, sends one TACACS+ packet, reads one response,
    /// and closes the connection.  No background tasks, no session
    /// multiplexing.  The outgoing packet includes the single-connect flag
    /// so the server's response reveals whether it supports multiplexing.
    async fn send_authorization_dedicated(
        &self,
        server: &TacacsPlusServer,
        request: &AuthorizationOperation,
    ) -> anyhow::Result<DedicatedOperationResult<AuthorizationOperationResponse>>;
}

/// Result of a one-shot request sent via [`DedicatedConnection`].
pub(crate) struct DedicatedOperationResult<Response> {
    /// The operation response mapped to domain types.
    pub response: Response,
    /// Whether the server indicated support for single-connection mode.
    pub single_connect_supported: bool,
}

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

/// Maps a TACACS+ protocol accounting status to the domain enum.
const fn accounting_status(status: TacacsAccountingStatus) -> AccountingResponseStatus {
    match status {
        TacacsAccountingStatus::TacPlusAcctStatusSuccess => AccountingResponseStatus::Success,
        TacacsAccountingStatus::TacPlusAcctStatusError => AccountingResponseStatus::Error,
        TacacsAccountingStatus::TacPlusAcctStatusFollow => AccountingResponseStatus::Follow,
    }
}

/// Converts a domain [`AccountingOperation`] into a TACACS+ accounting request
/// message with the standard service-level defaults (WATCHDOG flags, no
/// privilege level, shell service type).
fn build_accounting_request(request: &AccountingOperation) -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::START | TacacsAccountingFlags::STOP,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: request.user.clone(),
        port: request.port.clone(),
        rem_address: request.remote_address.clone(),
        args: build_accounting_args(&request.command, &request.command_arguments),
    }
}

/// Builds the TACACS+ argument list for an accounting request.
///
/// The resulting list always starts with `service=shell` and `cmd=<command>`,
/// followed by one `cmd-arg=<arg>` entry for each element of
/// `command_arguments`.
fn build_accounting_args(command: &str, command_arguments: &[String]) -> Vec<String> {
    let base_args = ["service=shell".to_owned(), format!("cmd={command}")];
    let extra_args = command_arguments.iter().map(|arg| format!("cmd-arg={arg}"));
    base_args.into_iter().chain(extra_args).collect()
}

/// Maps a TACACS+ protocol authorization status to the domain enum.
const fn authorization_status(status: TacacsAuthorizationStatus) -> AuthorizationResponseStatus {
    match status {
        TacacsAuthorizationStatus::TacPlusPassAdd => AuthorizationResponseStatus::PassAdd,
        TacacsAuthorizationStatus::TacPlusPassRepl => AuthorizationResponseStatus::PassRepl,
        TacacsAuthorizationStatus::TacPlusFail => AuthorizationResponseStatus::Fail,
        TacacsAuthorizationStatus::TacPlusError => AuthorizationResponseStatus::Error,
        TacacsAuthorizationStatus::TacPlusFollow => AuthorizationResponseStatus::Follow,
    }
}

/// Converts a domain [`AuthorizationOperation`] into a TACACS+ authorization
/// request message with service-level authentication context defaults.
fn build_authorization_request(
    request: &AuthorizationOperation,
) -> anyhow::Result<AuthorizationRequest> {
    let priv_lvl = u8::try_from(request.privilege_level)
        .context("authorization privilege level exceeds TACACS+ u8 field")?;
    Ok(AuthorizationRequest {
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus,
        priv_lvl,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeAscii,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
        user: request.user.clone(),
        port: request.port.clone(),
        rem_address: request.remote_address.clone(),
        args: request.args.iter().map(format_authorization_arg).collect(),
    })
}

fn format_authorization_arg(arg: &AuthorizationArg) -> String {
    let separator = if arg.mandatory {
        '='
    } else {
        '*'
    };
    format!("{}{separator}{}", arg.name, arg.value)
}

fn parse_authorization_args(args: Vec<String>) -> anyhow::Result<Vec<AuthorizationArg>> {
    args.into_iter()
        .map(|arg| AuthorizationArg::parse(&arg))
        .collect()
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
/// Sends a single accounting request over a [`DedicatedConnection`] — one
/// TCP connection, one packet out, one packet back, no background tasks.
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

/// Sends a single authorization request over a [`DedicatedConnection`] — one
/// TCP connection, one packet out, one packet back, no background tasks.
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

fn to_accounting_response(address: &str, reply: AccountingReply) -> AccountingOperationResponse {
    AccountingOperationResponse {
        server: address.to_owned(),
        status: accounting_status(reply.status),
        server_message: reply.server_msg,
        data: reply.data,
    }
}

fn to_authorization_response(
    address: &str,
    reply: AuthorizationReply,
) -> anyhow::Result<AuthorizationOperationResponse> {
    Ok(AuthorizationOperationResponse {
        server: address.to_owned(),
        status: authorization_status(reply.status),
        server_message: reply.server_msg,
        args: parse_authorization_args(reply.args)?,
        data: reply.data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_accounting_args() {
        let args = build_accounting_args("show", &["users".to_owned(), "brief".to_owned()]);
        assert_eq!(
            args,
            vec![
                "service=shell",
                "cmd=show",
                "cmd-arg=users",
                "cmd-arg=brief"
            ]
        );
    }

    #[test]
    fn test_build_accounting_request_uses_standard_fields_only() {
        let request = build_accounting_request(&AccountingOperation {
            user: "user".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned()],
        });
        assert_eq!(request.user, "user");
        assert_eq!(request.port, "tty0");
        assert_eq!(request.rem_address, "127.0.0.1");
        assert_eq!(request.args, vec!["service=shell", "cmd=show", "cmd-arg=users"]);
    }

    #[test]
    fn test_build_authorization_request_maps_domain_fields() {
        let request = build_authorization_request(
            &AuthorizationOperation::builder("admin", 15)
                .port("pts/1")
                .remote_address("192.0.2.10")
                .service("shell")
                .command("show")
                .command_arg("users")
                .build()
                .unwrap(),
        )
        .unwrap();

        assert_eq!(request.user, "admin");
        assert_eq!(request.port, "pts/1");
        assert_eq!(request.rem_address, "192.0.2.10");
        assert_eq!(request.priv_lvl, 15);
        assert_eq!(request.args, vec!["service=shell", "cmd=show", "cmd-arg=users"]);
    }
}
