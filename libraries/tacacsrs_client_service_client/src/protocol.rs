//! Domain-level request and response types for the local TACACS+ client API.
//!
//! The local IPC transport is defined in protobuf and served over gRPC, but the
//! rest of the crate works with these operation-centric Rust types so callers do
//! not have to depend on generated transport code directly.

use anyhow::{Context, bail};

use crate::ipc;

/// Client-supplied inputs for a TACACS+ accounting operation.
///
/// These fields intentionally stay at the RPC level instead of mirroring the
/// TACACS+ packet header. The service owns header flags, session identifiers,
/// and server selection on behalf of the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingOperation {
    /// TACACS+ username associated with the command being accounted for.
    pub user: String,
    /// NAS or tty/port identifier reported to the TACACS+ server.
    pub port: String,
    /// Remote client address to report in the TACACS+ accounting record.
    pub remote_address: String,
    /// Command name to report, matching the TACACS+ `cmd` accounting argument.
    pub command: String,
    /// Additional command arguments encoded as TACACS+ `cmd-arg` values.
    pub command_arguments: Vec<String>,
}

/// RFC-aware service response for a TACACS+ accounting operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingOperationResponse {
    /// Upstream TACACS+ server that handled the request.
    pub server: String,
    /// TACACS+ accounting reply status.
    ///
    /// This abstracts the RFC 8907 accounting status octet:
    /// - `success` => `TAC_PLUS_ACCT_STATUS_SUCCESS` (`0x01`)
    /// - `error` => `TAC_PLUS_ACCT_STATUS_ERROR` (`0x02`)
    /// - `follow` => `TAC_PLUS_ACCT_STATUS_FOLLOW` (`0x21`)
    pub status: AccountingResponseStatus,
    /// Human-readable message returned by the TACACS+ server.
    pub server_message: String,
    /// Optional opaque data returned by the TACACS+ server.
    pub data: String,
}

/// Normalized TACACS+ accounting reply status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingResponseStatus {
    /// `TAC_PLUS_ACCT_STATUS_SUCCESS` (`0x01`) indicates the accounting record
    /// was accepted successfully by the TACACS+ server.
    Success,
    /// `TAC_PLUS_ACCT_STATUS_ERROR` (`0x02`) indicates the server rejected the
    /// accounting operation or encountered an error processing it.
    Error,
    /// `TAC_PLUS_ACCT_STATUS_FOLLOW` (`0x21`) indicates the client should
    /// continue with a follow-up action defined by the server deployment.
    Follow,
}

impl AccountingResponseStatus {
    /// Returns the RFC status code carried in the TACACS+ accounting reply.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0x01,
            Self::Error => 0x02,
            Self::Follow => 0x21,
        }
    }

    fn into_proto(self) -> i32 {
        i32::from(self.code())
    }

    fn from_proto(value: i32) -> anyhow::Result<Self> {
        match u8::try_from(value).context("IPC accounting status value is out of u8 range")? {
            0 => bail!("IPC accounting status must not be unspecified"),
            0x01 => Ok(Self::Success),
            0x02 => Ok(Self::Error),
            0x21 => Ok(Self::Follow),
            _ => bail!("IPC accounting status value is not recognized"),
        }
    }
}

/// Structured error returned by the local service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// Error text suitable for logs and operator-facing diagnostics.
    pub message: String,
    /// Upstream server associated with the error, if one had already been chosen.
    pub server: Option<String>,
    /// Whether retrying against the service may succeed after failover or recovery.
    pub retriable: bool,
}

impl ServiceError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            server: None,
            retriable: false,
        }
    }

    #[must_use]
    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    #[must_use]
    pub const fn retriable(mut self, retriable: bool) -> Self {
        self.retriable = retriable;
        self
    }

    #[must_use]
    pub fn into_proto(self) -> ipc::ServiceError {
        ipc::ServiceError {
            message: self.message,
            server: self.server.unwrap_or_default(),
            retriable: self.retriable,
        }
    }

    #[must_use]
    pub fn from_proto(proto: ipc::ServiceError) -> Self {
        Self {
            message: proto.message,
            server: (!proto.server.is_empty()).then_some(proto.server),
            retriable: proto.retriable,
        }
    }
}

impl From<AccountingOperation> for ipc::AccountingRequest {
    fn from(value: AccountingOperation) -> Self {
        Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            command: value.command,
            command_arguments: value.command_arguments,
        }
    }
}

impl From<&AccountingOperation> for ipc::AccountingRequest {
    fn from(value: &AccountingOperation) -> Self {
        Self {
            user: value.user.clone(),
            port: value.port.clone(),
            remote_address: value.remote_address.clone(),
            command: value.command.clone(),
            command_arguments: value.command_arguments.clone(),
        }
    }
}

impl TryFrom<ipc::AccountingRequest> for AccountingOperation {
    type Error = anyhow::Error;

    fn try_from(value: ipc::AccountingRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            command: value.command,
            command_arguments: value.command_arguments,
        })
    }
}

impl AccountingOperationResponse {
    #[must_use]
    pub fn into_proto(self) -> ipc::AccountingResponse {
        ipc::AccountingResponse {
            server: self.server,
            status: self.status.into_proto(),
            server_message: self.server_message,
            data: self.data,
        }
    }

    /// Converts a protobuf accounting response into the typed domain response.
    ///
    /// # Errors
    ///
    /// Returns an error if the protobuf status code is missing, out of range, or
    /// not one of the supported TACACS+ accounting reply status values.
    pub fn from_proto(proto: ipc::AccountingResponse) -> anyhow::Result<Self> {
        Ok(Self {
            server: proto.server,
            status: AccountingResponseStatus::from_proto(proto.status)?,
            server_message: proto.server_message,
            data: proto.data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accounting_response_status_codes_match_rfc_values() {
        assert_eq!(AccountingResponseStatus::Success.code(), 0x01);
        assert_eq!(AccountingResponseStatus::Error.code(), 0x02);
        assert_eq!(AccountingResponseStatus::Follow.code(), 0x21);
    }

    #[test]
    fn test_accounting_operation_proto_round_trip() {
        let request = AccountingOperation {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned()],
        };

        let encoded: ipc::AccountingRequest = (&request).into();
        let decoded = AccountingOperation::try_from(encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn test_service_error_proto_round_trip() {
        let error = ServiceError::new("failed")
            .with_server("server-a:49")
            .retriable(true);

        let decoded = ServiceError::from_proto(error.clone().into_proto());
        assert_eq!(decoded, error);
    }
}
