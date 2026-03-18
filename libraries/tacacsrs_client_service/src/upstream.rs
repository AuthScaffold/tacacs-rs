//! Persistent upstream TACACS+ connection management.
//!
//! This module adapts the lower-level networking/session APIs into the
//! service's higher-level operation model. Each upstream connection can be
//! reused for many IPC requests, while the service keeps ownership of failover
//! decisions and connection lifecycle.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType,
};
use tacacsrs_client_service_client::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus,
};
use tacacsrs_networking::helpers::tls_server_name;
use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionManagementTrait;
use tacacsrs_networking::{connection::TacacsConnection, transport::tls::TlsConfigurationBuilder};
#[cfg(feature = "psk")]
use tacacsrs_networking::transport::tls_psk::{PskConfigurationBuilder, PskIdentity};

/// Connection options shared by all upstream TACACS+ server connections.
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
pub(crate) trait UpstreamConnection: Send + Sync {
    fn server_address(&self) -> &str;
    async fn is_usable_for_new_sessions(&self) -> bool;
    async fn send_accounting(
        &self,
        request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse>;
}

#[async_trait]
/// Creates upstream connections for a configured TACACS+ server address.
pub(crate) trait UpstreamConnector: Send + Sync {
    async fn connect(&self, address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>>;
}

/// Production connector backed by `tacacsrs_networking`.
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
}

struct TacacsUpstreamConnection {
    server_address: String,
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

    async fn send_accounting(
        &self,
        request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        let session = self
            .connection
            .create_session()
            .await
            .with_context(|| format!("Failed to create session on {}", self.server_address))?;

        let response = session
            .send_accounting_request(build_accounting_request(request))
            .await
            .with_context(|| {
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

fn accounting_status(status: TacacsAccountingStatus) -> AccountingResponseStatus {
    match status {
        TacacsAccountingStatus::TacPlusAcctStatusSuccess => AccountingResponseStatus::Success,
        TacacsAccountingStatus::TacPlusAcctStatusError => AccountingResponseStatus::Error,
        TacacsAccountingStatus::TacPlusAcctStatusFollow => AccountingResponseStatus::Follow,
    }
}

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

fn build_accounting_args(command: &str, command_arguments: &[String]) -> Vec<String> {
    let base_args = ["service=shell".to_owned(), format!("cmd={command}")];
    let extra_args = command_arguments.iter().map(|arg| format!("cmd-arg={arg}"));
    base_args.into_iter().chain(extra_args).collect()
}

async fn connect_upstream(
    address: &str,
    options: &UpstreamConnectionOptions,
) -> anyhow::Result<Arc<TacacsConnection>> {
    let stream = tokio::time::timeout(
        options.connect_timeout,
        tacacsrs_networking::helpers::connect_tcp(address),
    )
    .await
    .with_context(|| format!("Timed out connecting to {address}"))?
    .with_context(|| format!("Failed to establish TCP connection to {address}"))?;

    let connection =
        Arc::new(TacacsConnection::new(options.obfuscation_key.as_deref().map(str::as_bytes)));

    if options.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (options.psk_identity.as_ref(), options.psk_key.as_ref())
        {
            let psk = PskIdentity::new(psk_identity, psk_key.as_bytes())
                .context("Invalid PSK credentials")?;
            let tls_stream = PskConfigurationBuilder::new(psk)
                .connect(stream)
                .await
                .context("Failed to establish TLS PSK connection")?;
            connection
                .run(tls_stream)
                .await
                .context("Failed to start TLS PSK connection handler")?;
            return Ok(connection);
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

        let tls_stream = tacacsrs_networking::transport::tls::connect_tls(
            &tls_config,
            stream,
            tls_server_name(address),
        )
        .await
        .context("Failed to establish TLS connection")?;

        connection
            .run(tls_stream)
            .await
            .context("Failed to start TLS connection handler")?;
    } else {
        connection
            .run(stream)
            .await
            .context("Failed to start TCP connection handler")?;
    }

    Ok(connection)
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
