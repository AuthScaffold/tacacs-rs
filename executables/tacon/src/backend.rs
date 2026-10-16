//! Execution backend for the `tacon` client.
//!
//! A single `Backend` value is the resolved execution path for one CLI
//! invocation: a direct TACACS+ connection, or on Linux the local agent IPC
//! channel. The single-command dispatcher and the batch engine run every AAA
//! operation through the same `Backend` methods, so direct and IPC execution
//! share one code path. Backend-specific concerns (connection establishment,
//! direct probe configuration, and IPC retry behavior) stay outside this enum.

#[cfg(target_os = "linux")]
use std::str::FromStr;

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse, PapAuthenticationOperation, PapAuthenticationOperationResponse,
};

use crate::commands;
use crate::connection::Connection;

/// Resolved execution backend for AAA operations.
///
/// Windows builds support only the direct connection path. The agent IPC
/// variant is Linux-only, which keeps the platform matrix explicit.
#[derive(Clone)]
pub(crate) enum Backend {
    /// A direct TACACS+ connection (adaptive single-connection or dedicated).
    Direct(Connection),

    /// The local central-agent IPC channel and its persistent SDK client.
    #[cfg(target_os = "linux")]
    Service(ServiceClient),
}

impl Backend {
    /// Runs one accounting operation against this backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the direct exchange or the IPC request fails.
    pub(crate) async fn accounting(
        &self,
        operation: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        match self {
            Self::Direct(connection) => {
                commands::accounting::send_direct(connection, operation).await
            }
            #[cfg(target_os = "linux")]
            Self::Service(client) => client
                .send_accounting(operation.clone())
                .await
                .map_err(Into::into),
        }
    }

    /// Runs one shell authorization operation against this backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the direct exchange or the IPC request fails.
    pub(crate) async fn authorization(
        &self,
        operation: &AuthorizationOperation,
    ) -> anyhow::Result<AuthorizationOperationResponse> {
        match self {
            Self::Direct(connection) => {
                commands::authorization::send_direct(connection, operation).await
            }
            #[cfg(target_os = "linux")]
            Self::Service(client) => client
                .send_authorization(operation.clone())
                .await
                .map_err(Into::into),
        }
    }

    /// Runs one fixed PAP authentication operation against this backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the direct exchange or the IPC request fails.
    pub(crate) async fn pap_authentication(
        &self,
        operation: &PapAuthenticationOperation,
    ) -> anyhow::Result<PapAuthenticationOperationResponse> {
        match self {
            Self::Direct(connection) => {
                commands::authentication::send_direct(connection, operation).await
            }
            #[cfg(target_os = "linux")]
            Self::Service(client) => client
                .authenticate_pap(operation.clone())
                .await
                .map_err(Into::into),
        }
    }
}

/// Connects the persistent agent IPC client for the given endpoint string.
///
/// The returned [`ServiceClient`] owns a reusable channel that callers clone to
/// share across concurrent requests.
///
/// # Errors
///
/// Returns an error if the endpoint is invalid or the service cannot be reached.
#[cfg(target_os = "linux")]
pub(crate) async fn connect_service(endpoint: &str) -> anyhow::Result<ServiceClient> {
    let endpoint = IpcEndpoint::from_str(endpoint).context("Invalid service endpoint")?;
    ServiceClient::connect(endpoint)
        .await
        .context("Failed to connect to TACACS+ service")
}
