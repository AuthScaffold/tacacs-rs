//! Persistent upstream TACACS+ connection management.
//!
//! This module adapts the lower-level networking/session APIs into the
//! service's higher-level operation model. Each upstream connection can be
//! reused for many IPC requests, while the service keeps ownership of failover
//! decisions and connection lifecycle.
//!
//! # Transport selection
//!
//! The [`UpstreamConnectionOptions`] type controls which transport is used for
//! each upstream TACACS+ connection:
//!
//! | Configuration | Transport |
//! |---------------|-----------|
//! | `use_tls = false` | Plain TCP |
//! | `use_tls = true` + client cert | mTLS (X.509) |
//! | `use_tls = true` + PSK identity | TLS-PSK (feature-gated) |
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
use std::time::Duration;

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
use tacacsrs_networking::SingleConnectionState;
use tacacsrs_networking::dedicated_connection::DedicatedConnection;
use tacacsrs_networking::helpers::tls_server_name;
use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionManagementTrait;
use tacacsrs_networking::{connection::TacacsConnection, transport::tls::TlsConfigurationBuilder};
#[cfg(feature = "psk")]
use tacacsrs_networking::transport::tls_psk::{PskConfigurationBuilder, PskIdentity};

/// Connection options shared by all upstream TACACS+ server connections.
///
/// These options are configured once at service startup and applied uniformly
/// to every upstream connection attempt. The service creates a network
/// connector from these options and passes it to the
/// internal failover state machine.
///
/// # Connection selection
///
/// ```text
/// IPC Request ──> ServiceState
///                     |
///              cached connection usable?
///                /              \
///              Yes               No
///               |                 |
///         Reuse connection   UpstreamConnector
///               |                 |
///               |          TLS enabled?
///               |         /    |     \
///               |       mTLS  PSK  Plain TCP
///               |         \    |     /
///               |      TacacsConnection
///               |             |
///               +------+------+
///                      |
///               Create TACACS+ session
/// ```
///
/// # Defaults
///
/// | Field | Default |
/// |-------|---------|
/// | `obfuscation_key` | `None` |
/// | `use_tls` | `false` |
/// | `client_certificate` | `None` |
/// | `client_key` | `None` |
/// | `insecure_disable_certificate_verification` | `false` |
/// | `connect_timeout` | 5 seconds |
#[derive(Debug, Clone)]
pub struct UpstreamConnectionOptions {
    /// Optional TACACS+ obfuscation key for legacy/non-TLS exchanges.
    pub obfuscation_key: Option<String>,
    /// Whether the service should use TLS for upstream TACACS+ connections.
    pub use_tls: bool,
    /// Optional client certificate path for mTLS upstream connections.
    pub client_certificate: Option<String>,
    /// Optional private key path matching `client_certificate`.
    pub client_key: Option<String>,
    #[cfg(feature = "psk")]
    /// Optional TLS-PSK identity for feature-gated PSK upstream transport.
    pub psk_identity: Option<String>,
    #[cfg(feature = "psk")]
    /// Optional TLS-PSK key for feature-gated PSK upstream transport.
    pub psk_key: Option<String>,
    /// Dangerously disable upstream TLS certificate verification.
    ///
    /// This exists only for development or controlled environments using
    /// self-signed or otherwise untrusted certificates.
    pub insecure_disable_certificate_verification: bool,
    /// Timeout applied while establishing a fresh upstream TCP connection.
    pub connect_timeout: Duration,
}

impl Default for UpstreamConnectionOptions {
    fn default() -> Self {
        Self {
            obfuscation_key: None,
            use_tls: false,
            client_certificate: None,
            client_key: None,
            #[cfg(feature = "psk")]
            psk_identity: None,
            #[cfg(feature = "psk")]
            psk_key: None,
            insecure_disable_certificate_verification: false,
            connect_timeout: Duration::from_secs(5),
        }
    }
}

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
/// Creates upstream connections for a configured TACACS+ server address.
///
/// The connector is called by [`ServiceState`](crate::service) whenever a
/// fresh upstream connection is needed—either during startup warm-up or when
/// a cached connection is no longer usable.
pub(crate) trait UpstreamConnector: Send + Sync {
    /// Establishes a new connection to the given TACACS+ server address.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, TLS handshake, or TACACS+
    /// connection setup fails.
    async fn connect(&self, address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>>;

    /// Sends a single accounting request over a dedicated one-shot connection.
    ///
    /// Opens a TCP connection, sends one TACACS+ packet, reads one response,
    /// and closes the connection.  No background tasks, no session
    /// multiplexing.  The outgoing packet includes the single-connect flag
    /// so the server's response reveals whether it supports multiplexing.
    async fn send_accounting_dedicated(
        &self,
        address: &str,
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
/// Takes a snapshot of [`UpstreamConnectionOptions`] at construction time and
/// applies those options to every upstream connection it creates.
#[derive(Debug, Clone)]
pub(crate) struct NetworkUpstreamConnector {
    options: UpstreamConnectionOptions,
}

impl NetworkUpstreamConnector {
    #[must_use]
    pub(crate) fn new(options: UpstreamConnectionOptions) -> Self {
        Self { options }
    }
}

#[async_trait]
impl UpstreamConnector for NetworkUpstreamConnector {
    async fn connect(&self, address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let connection = connect_upstream(address, &self.options).await?;
        Ok(Arc::new(TacacsUpstreamConnection {
            server_address: address.to_owned(),
            connection,
        }))
    }

    async fn send_accounting_dedicated(
        &self,
        address: &str,
        request: &AccountingOperation,
    ) -> anyhow::Result<DedicatedAccountingResult> {
        send_dedicated_accounting(address, &self.options, request).await
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
fn accounting_status(status: TacacsAccountingStatus) -> AccountingResponseStatus {
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
/// 2. If TLS is enabled, negotiate the TLS handshake (mTLS or PSK).
/// 3. Start the TACACS+ connection handler on the resulting stream.
///
/// # Errors
///
/// Returns an error if TCP connection times out, TLS negotiation fails, or
/// the TACACS+ connection handler cannot start.
async fn connect_upstream(
    address: &str,
    options: &UpstreamConnectionOptions,
) -> anyhow::Result<Arc<TacacsConnection>> {
    log::debug!(
        "Connecting to upstream TACACS+ server {address} (TLS: {}, timeout: {:?})",
        options.use_tls,
        options.connect_timeout,
    );

    let stream = tokio::time::timeout(
        options.connect_timeout,
        tacacsrs_networking::helpers::connect_tcp(address),
    )
    .await
    .with_context(|| {
        log::warn!("Connection to {address} timed out after {:?}", options.connect_timeout,);
        format!("Timed out connecting to {address}")
    })?
    .with_context(|| {
        log::warn!("TCP connection to {address} failed");
        format!("Failed to establish TCP connection to {address}")
    })?;

    log::debug!("TCP connection to {address} established");

    let connection =
        Arc::new(TacacsConnection::new(options.obfuscation_key.as_deref().map(str::as_bytes)));

    if options.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (options.psk_identity.as_ref(), options.psk_key.as_ref())
        {
            log::debug!("Negotiating TLS-PSK handshake with {address}");
            let psk = PskIdentity::new(psk_identity, psk_key.as_bytes())
                .context("Invalid PSK credentials")?;
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
            return Ok(connection);
        }

        log::debug!("Negotiating mTLS handshake with {address}");

        let client_cert = options
            .client_certificate
            .as_ref()
            .context("TLS requires a client certificate or PSK credentials")?;
        let client_key = options
            .client_key
            .as_ref()
            .context("TLS requires a client key or PSK credentials")?;

        let tls_config = Arc::new(
            TlsConfigurationBuilder::new()
                .with_client_auth_cert_files(client_cert, client_key)
                .await
                .inspect_err(|e| log::warn!("Failed to load TLS certificates for {address}: {e:#}"))
                .context("Failed to load TLS certificates")?
                .with_certificate_verification_disabled(
                    options.insecure_disable_certificate_verification,
                )
                .build()
                .inspect_err(|e| log::warn!("Failed to build TLS config for {address}: {e:#}"))
                .context("Failed to build TLS configuration")?,
        );

        let tls_stream = tacacsrs_networking::transport::tls::connect_tls(
            &tls_config,
            stream,
            tls_server_name(address),
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
    } else {
        connection
            .run(stream)
            .await
            .inspect_err(|e| {
                log::warn!("TCP connection handler start for {address} failed: {e:#}");
            })
            .context("Failed to start TCP connection handler")?;
        log::debug!("TCP connection to {address} ready");
    }

    Ok(connection)
}

/// Sends a single accounting request over a [`DedicatedConnection`] — one
/// TCP connection, one packet out, one packet back, no background tasks.
async fn send_dedicated_accounting(
    address: &str,
    options: &UpstreamConnectionOptions,
    request: &AccountingOperation,
) -> anyhow::Result<DedicatedAccountingResult> {
    log::debug!(
        "Dedicated accounting request to {address} (TLS: {}, timeout: {:?})",
        options.use_tls,
        options.connect_timeout,
    );

    let stream = tokio::time::timeout(
        options.connect_timeout,
        tacacsrs_networking::helpers::connect_tcp(address),
    )
    .await
    .with_context(|| format!("Timed out connecting to {address}"))?
    .with_context(|| format!("Failed to establish TCP connection to {address}"))?;

    let obfuscation_key = options.obfuscation_key.as_deref().map(str::as_bytes);
    let tacacs_request = build_accounting_request(request);

    let exchange = if options.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (options.psk_identity.as_ref(), options.psk_key.as_ref())
        {
            let psk = PskIdentity::new(psk_identity, psk_key.as_bytes())
                .context("Invalid PSK credentials")?;
            let tls_stream =
                timeout(options.connect_timeout, PskConfigurationBuilder::new(psk).connect(stream))
                    .await
                    .map_err(|_| anyhow::anyhow!("TLS PSK handshake timed out"))?
                    .context("Failed to establish TLS PSK connection")?;
            let mut conn = DedicatedConnection::new(tls_stream, obfuscation_key);
            return conn
                .send_accounting(tacacs_request, TacacsFlags::empty())
                .await
                .map(|ex| to_dedicated_result(address, ex));
        }

        let client_cert = options
            .client_certificate
            .as_ref()
            .context("TLS requires a client certificate or PSK credentials")?;
        let client_key = options
            .client_key
            .as_ref()
            .context("TLS requires a client key or PSK credentials")?;

        let tls_config = Arc::new(
            TlsConfigurationBuilder::new()
                .with_client_auth_cert_files(client_cert, client_key)
                .await
                .context("Failed to load TLS certificates")?
                .with_certificate_verification_disabled(
                    options.insecure_disable_certificate_verification,
                )
                .build()
                .context("Failed to build TLS configuration")?,
        );

        let tls_stream = timeout(
            options.connect_timeout,
            tacacsrs_networking::transport::tls::connect_tls(
                &tls_config,
                stream,
                tls_server_name(address),
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))?
        .context("Failed to establish TLS connection")?;

        let mut conn = DedicatedConnection::new(tls_stream, obfuscation_key);
        conn.send_accounting(tacacs_request, TacacsFlags::empty())
            .await?
    } else {
        let mut conn = DedicatedConnection::new(stream, obfuscation_key);
        conn.send_accounting(tacacs_request, TacacsFlags::empty())
            .await?
    };

    log::debug!(
        "Dedicated accounting response from {address}: status={:?}, single_connect={}",
        exchange.reply.status,
        exchange.single_connect_supported,
    );

    Ok(to_dedicated_result(address, exchange))
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
