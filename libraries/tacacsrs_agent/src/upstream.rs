//! Persistent upstream TACACS+ connection management.
//!
//! This module adapts the lower-level networking/session APIs into the
//! service's higher-level operation model. Each upstream connection can be
//! reused for many IPC requests, while the service keeps ownership of failover
//! decisions and connection lifecycle.
//!
//! # Transport selection
//!
//! Each [`tacacsrs_config::ServerConnectionConfig`] carries a
//! [`tacacsrs_config::ResolvedSecurity`] variant that
//! determines which transport is used for the upstream TACACS+ connection:
//!
//! | Security | Transport |
//! |----------|-----------|
//! | `Obfuscation` | Plain TCP |
//! | `Tls` | mTLS (X.509) |
//! | `Psk` | TLS-PSK (feature-gated) |
//!
//! Certificate verification is enabled by default. The
//! `insecure_disable_certificate_verification` flag exists only for
//! development environments using self-signed certificates.
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
use tokio::time::timeout;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType, TacacsFlags,
};
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus,
};
use tacacsrs_config::{ResolvedSecurity, ServerConnectionConfig};
use tacacsrs_networking::SingleConnectionState;
use tacacsrs_networking::dedicated_connection::DedicatedConnection;
use tacacsrs_networking::helpers::tls_server_name;
use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionManagementTrait;
use tacacsrs_networking::{connection::TacacsConnection, transport::tls::TlsConfigurationBuilder};
#[cfg(feature = "psk")]
use tacacsrs_networking::transport::tls_psk::{PskConfigurationBuilder, PskIdentity};

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
        server: &ServerConnectionConfig,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>>;

    /// Sends a single accounting request over a dedicated one-shot connection.
    ///
    /// Opens a TCP connection, sends one TACACS+ packet, reads one response,
    /// and closes the connection.  No background tasks, no session
    /// multiplexing.  The outgoing packet includes the single-connect flag
    /// so the server's response reveals whether it supports multiplexing.
    async fn send_accounting_dedicated(
        &self,
        server: &ServerConnectionConfig,
        request: &AccountingOperation,
    ) -> anyhow::Result<DedicatedAccountingResult>;
}

/// Result of a one-shot accounting request sent via [`DedicatedConnection`].
pub(crate) struct DedicatedAccountingResult {
    /// The accounting response mapped to domain types.
    pub response: AccountingOperationResponse,
    /// Whether the server indicated support for single-connection mode.
    pub single_connect_supported: bool,
}

/// Production connector backed by [`tacacsrs_networking`].
///
/// Extracts per-server connection parameters from the provided
/// [`ServerConnectionConfig`] at each connection attempt.
#[derive(Debug, Clone)]
pub(crate) struct NetworkUpstreamConnector;

#[async_trait]
impl UpstreamConnector for NetworkUpstreamConnector {
    async fn connect(
        &self,
        server: &ServerConnectionConfig,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let address = server.socket_address();
        let connection = connect_upstream(server).await?;
        Ok(Arc::new(TacacsUpstreamConnection {
            server_address: address,
            connection,
        }))
    }

    async fn send_accounting_dedicated(
        &self,
        server: &ServerConnectionConfig,
        request: &AccountingOperation,
    ) -> anyhow::Result<DedicatedAccountingResult> {
        send_dedicated_accounting(server, request).await
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
        log::debug!(
            "Creating TACACS+ session on {} for accounting request (user={}, cmd={})",
            self.server_address,
            request.user,
            request.command,
        );

        let session = self
            .connection
            .create_session()
            .await
            .with_context(|| format!("Failed to create session on {}", self.server_address))?;

        let response = session
            .send_accounting_request(build_accounting_request(request))
            .await;

        match &response {
            Ok(resp) => {
                log::debug!(
                    "Accounting response from {}: status={:?}, server_msg={}",
                    self.server_address,
                    resp.status,
                    if resp.server_msg.is_empty() {
                        "(empty)"
                    } else {
                        &resp.server_msg
                    },
                );
            }
            Err(error) => {
                log::warn!("Accounting request to {} failed: {error:#}", self.server_address,);
            }
        }

        let response = response.with_context(|| {
            format!("Failed to send accounting request via {}", self.server_address)
        })?;

        Ok(AccountingOperationResponse {
            server: self.server_address.clone(),
            status: accounting_status(response.status),
            server_message: response.server_msg,
            data: response.data,
        })
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
#[allow(clippy::too_many_lines)]
async fn connect_upstream(
    server: &ServerConnectionConfig,
) -> anyhow::Result<Arc<TacacsConnection>> {
    let address = server.socket_address();

    log::debug!(
        "Connecting to upstream TACACS+ server {address} (security: {}, timeout: {:?})",
        match &server.security {
            ResolvedSecurity::Obfuscation { .. } => "obfuscation",
            ResolvedSecurity::Tls { .. } => "tls",
            ResolvedSecurity::Psk { .. } => "psk",
        },
        server.timeout,
    );

    let stream =
        tokio::time::timeout(server.timeout, tacacsrs_networking::helpers::connect_tcp(&address))
            .await
            .with_context(|| {
                log::warn!("Connection to {address} timed out after {:?}", server.timeout);
                format!("Timed out connecting to {address}")
            })?
            .with_context(|| {
                log::warn!("TCP connection to {address} failed");
                format!("Failed to establish TCP connection to {address}")
            })?;

    log::debug!("TCP connection to {address} established");

    match &server.security {
        ResolvedSecurity::Obfuscation { shared_secret } => {
            let connection =
                Arc::new(TacacsConnection::new(shared_secret.as_deref().map(str::as_bytes)));
            connection
                .run(stream)
                .await
                .inspect_err(|e| {
                    log::warn!("TCP connection handler start for {address} failed: {e:#}");
                })
                .context("Failed to start TCP connection handler")?;
            log::debug!("TCP connection to {address} ready");
            Ok(connection)
        }
        ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem: _,
            insecure_disable_certificate_verification,
        } => {
            log::debug!("Negotiating mTLS handshake with {address}");

            let connection = Arc::new(TacacsConnection::new(None));

            let mut builder = TlsConfigurationBuilder::new();
            if let (Some(cert), Some(key)) = (client_cert_pem, client_key_pem) {
                builder = builder
                    .with_client_auth_cert_pem(cert, key)
                    .inspect_err(|e| {
                        log::warn!("Failed to load TLS certificates for {address}: {e:#}");
                    })
                    .context("Failed to load TLS certificates")?;
            }

            let tls_config = Arc::new(
                builder
                    .with_certificate_verification_disabled(
                        *insecure_disable_certificate_verification,
                    )
                    .build()
                    .inspect_err(|e| log::warn!("Failed to build TLS config for {address}: {e:#}"))
                    .context("Failed to build TLS configuration")?,
            );

            let tls_stream = tacacsrs_networking::transport::tls::connect_tls(
                &tls_config,
                stream,
                tls_server_name(&address),
            )
            .await
            .inspect_err(|e| log::warn!("TLS handshake with {address} failed: {e:#}"))
            .context("Failed to establish TLS connection")?;

            connection
                .run(tls_stream)
                .await
                .inspect_err(|e| {
                    log::warn!("TLS connection handler start for {address} failed: {e:#}");
                })
                .context("Failed to start TLS connection handler")?;
            log::debug!("TLS connection to {address} ready");
            Ok(connection)
        }
        #[cfg(feature = "psk")]
        ResolvedSecurity::Psk { identity, key } => {
            log::debug!("Negotiating TLS-PSK handshake with {address}");

            let connection = Arc::new(TacacsConnection::new(None));

            let psk =
                PskIdentity::new(identity, key.as_bytes()).context("Invalid PSK credentials")?;
            let tls_stream = PskConfigurationBuilder::new(psk)
                .connect(stream)
                .await
                .inspect_err(|e| log::warn!("TLS-PSK handshake with {address} failed: {e:#}"))
                .context("Failed to establish TLS PSK connection")?;
            connection
                .run(tls_stream)
                .await
                .inspect_err(|e| {
                    log::warn!("TLS-PSK connection handler start for {address} failed: {e:#}");
                })
                .context("Failed to start TLS PSK connection handler")?;
            log::debug!("TLS-PSK connection to {address} ready");
            Ok(connection)
        }
        #[cfg(not(feature = "psk"))]
        ResolvedSecurity::Psk { .. } => {
            anyhow::bail!("PSK support is not enabled; rebuild with the `psk` feature flag")
        }
    }
}

/// Sends a single accounting request over a [`DedicatedConnection`] — one
/// TCP connection, one packet out, one packet back, no background tasks.
async fn send_dedicated_accounting(
    server: &ServerConnectionConfig,
    request: &AccountingOperation,
) -> anyhow::Result<DedicatedAccountingResult> {
    let address = server.socket_address();

    log::debug!(
        "Dedicated accounting request to {address} (security: {}, timeout: {:?})",
        match &server.security {
            ResolvedSecurity::Obfuscation { .. } => "obfuscation",
            ResolvedSecurity::Tls { .. } => "tls",
            ResolvedSecurity::Psk { .. } => "psk",
        },
        server.timeout,
    );

    let stream =
        tokio::time::timeout(server.timeout, tacacsrs_networking::helpers::connect_tcp(&address))
            .await
            .with_context(|| format!("Timed out connecting to {address}"))?
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?;

    let tacacs_request = build_accounting_request(request);

    let exchange = match &server.security {
        ResolvedSecurity::Obfuscation { shared_secret } => {
            let obfuscation_key = shared_secret.as_deref().map(str::as_bytes);
            let mut conn = DedicatedConnection::new(stream, obfuscation_key);
            conn.send_accounting(tacacs_request, TacacsFlags::empty())
                .await?
        }
        ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem: _,
            insecure_disable_certificate_verification,
        } => {
            let mut builder = TlsConfigurationBuilder::new();
            if let (Some(cert), Some(key)) = (client_cert_pem, client_key_pem) {
                builder = builder
                    .with_client_auth_cert_pem(cert, key)
                    .context("Failed to load TLS certificates")?;
            }

            let tls_config = Arc::new(
                builder
                    .with_certificate_verification_disabled(
                        *insecure_disable_certificate_verification,
                    )
                    .build()
                    .context("Failed to build TLS configuration")?,
            );

            let tls_stream = timeout(
                server.timeout,
                tacacsrs_networking::transport::tls::connect_tls(
                    &tls_config,
                    stream,
                    tls_server_name(&address),
                ),
            )
            .await
            .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))?
            .context("Failed to establish TLS connection")?;

            let mut conn = DedicatedConnection::new(tls_stream, None);
            conn.send_accounting(tacacs_request, TacacsFlags::empty())
                .await?
        }
        #[cfg(feature = "psk")]
        ResolvedSecurity::Psk { identity, key } => {
            let psk =
                PskIdentity::new(identity, key.as_bytes()).context("Invalid PSK credentials")?;
            let tls_stream =
                timeout(server.timeout, PskConfigurationBuilder::new(psk).connect(stream))
                    .await
                    .map_err(|_| anyhow::anyhow!("TLS PSK handshake timed out"))?
                    .context("Failed to establish TLS PSK connection")?;
            let mut conn = DedicatedConnection::new(tls_stream, None);
            return conn
                .send_accounting(tacacs_request, TacacsFlags::empty())
                .await
                .map(|ex| to_dedicated_result(&address, ex));
        }
        #[cfg(not(feature = "psk"))]
        ResolvedSecurity::Psk { .. } => {
            anyhow::bail!("PSK support is not enabled; rebuild with the `psk` feature flag")
        }
    };

    log::debug!(
        "Dedicated accounting response from {address}: status={:?}, single_connect={}",
        exchange.reply.status,
        exchange.single_connect_supported,
    );

    Ok(to_dedicated_result(&address, exchange))
}

fn to_dedicated_result(
    address: &str,
    exchange: tacacsrs_networking::ExchangeResult,
) -> DedicatedAccountingResult {
    DedicatedAccountingResult {
        response: AccountingOperationResponse {
            server: address.to_owned(),
            status: accounting_status(exchange.reply.status),
            server_message: exchange.reply.server_msg,
            data: exchange.reply.data,
        },
        single_connect_supported: exchange.single_connect_supported,
    }
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
}
