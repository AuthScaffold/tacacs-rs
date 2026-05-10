//! Domain-level request and response types for the local TACACS+ client API.
//!
//! The local IPC transport is defined in protobuf and served over gRPC, but the
//! rest of the crate works with these operation-centric Rust types so callers do
//! not have to depend on generated transport code directly.
//!
//! # Design rationale
//!
//! These types intentionally mirror the **logical operation** rather than the
//! TACACS+ packet layout. The service owns header flags, session identifiers,
//! and server selection on behalf of the caller. This keeps the client-facing
//! API stable even if the underlying TACACS+ encoding changes.
//!
//! # Protobuf conversions
//!
//! Each domain type has symmetric conversion to/from its protobuf counterpart:
//!
//! | Domain type | Proto direction | Method |
//! |-------------|----------------|--------|
//! | [`AccountingOperation`] | → `ipc::AccountingRequest` | `From` / `Into` |
//! | `ipc::AccountingRequest` | → [`AccountingOperation`] | `TryFrom` |
//! | [`AccountingOperationResponse`] | → `ipc::AccountingResponse` | `into_proto()` |
//! | `ipc::AccountingResponse` | → [`AccountingOperationResponse`] | `from_proto()` |
//! | [`AuthorizationOperation`] | → `ipc::AuthorizationRequest` | `From` / `Into` |
//! | `ipc::AuthorizationRequest` | → [`AuthorizationOperation`] | `TryFrom` |
//! | [`AuthorizationOperationResponse`] | → `ipc::AuthorizationResponse` | `into_proto()` |
//! | `ipc::AuthorizationResponse` | → [`AuthorizationOperationResponse`] | `from_proto()` |
//! | [`ServiceError`] | ↔ `ipc::ServiceError` | `into_proto()` / `from_proto()` |

use anyhow::{Context, bail};

use crate::ipc;

/// Client-supplied inputs for a TACACS+ accounting operation.
///
/// These fields intentionally stay at the RPC level instead of mirroring the
/// TACACS+ packet header. The service owns header flags, session identifiers,
/// and server selection on behalf of the caller.
///
/// # Protocol type relationships
///
/// ```text
/// AccountingOperation          AccountingOperationResponse
/// +---------------------+      +-----------------------------+
/// | user: String        |      | server: String              |
/// | port: String        |      | status: ResponseStatus -----+--> AccountingResponseStatus
/// | remote_address: Str |      | server_message: String      |    +----------+
/// | command: String     |      | data: String                |    | Success  |
/// | command_arguments:  |      +-----------------------------+    | Error    |
/// |   Vec<String>       |                                         | Follow   |
/// +---------------------+      ServiceError                      +----------+
///                               +-----------------------------+
///                               | message: String             |
///                               | server: Option<String>      |
///                               | retriable: bool             |
///                               +-----------------------------+
/// ```
///
/// # Field mapping
///
/// When the service forwards this operation to an upstream TACACS+ server it
/// builds a `TAC_PLUS_ACCT` request body with the following argument encoding:
///
/// | Field | TACACS+ argument |
/// |-------|-----------------|
/// | `command` | `cmd=<value>` |
/// | `command_arguments[i]` | `cmd-arg=<value>` |
///
/// The `service=shell` argument is always included automatically.
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
///
/// Returned by [`ServiceClient::send_accounting`](crate::ServiceClient::send_accounting)
/// on success. The response includes the upstream server that handled the
/// request and the TACACS+ accounting reply status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingOperationResponse {
    /// Upstream TACACS+ server that handled the request (e.g. `"tacacs.corp:49"`).
    pub server: String,
    /// TACACS+ accounting reply status.
    ///
    /// This abstracts the RFC 8907 accounting status octet:
    /// - [`Success`](AccountingResponseStatus::Success) ⇒ `TAC_PLUS_ACCT_STATUS_SUCCESS` (`0x01`)
    /// - [`Error`](AccountingResponseStatus::Error) ⇒ `TAC_PLUS_ACCT_STATUS_ERROR` (`0x02`)
    /// - [`Follow`](AccountingResponseStatus::Follow) ⇒ `TAC_PLUS_ACCT_STATUS_FOLLOW` (`0x21`)
    pub status: AccountingResponseStatus,
    /// Human-readable message returned by the TACACS+ server.
    pub server_message: String,
    /// Optional opaque data returned by the TACACS+ server.
    pub data: String,
}

/// Client-supplied inputs for a TACACS+ authorization operation.
///
/// This is the IPC-level contract used by local command mediation code. The
/// service field is typically `"shell"` for exec supervision, and command
/// arguments are represented without the `cmd-arg=` TACACS+ wire prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationOperation {
    /// TACACS+ username associated with the command being authorized.
    pub user: String,
    /// NAS or tty/port identifier reported to the TACACS+ server.
    pub port: String,
    /// Remote client address to report in the TACACS+ authorization request.
    pub remote_address: String,
    /// TACACS+ service name, for example `"shell"`.
    pub service: String,
    /// Command name to authorize.
    pub command: String,
    /// Command arguments to authorize.
    pub command_arguments: Vec<String>,
    /// TACACS+ privilege level for the command context.
    pub privilege_level: u32,
}

/// RFC-aware service response for a TACACS+ authorization operation.
///
/// Returned by [`ServiceClient::send_authorization`](crate::ServiceClient::send_authorization)
/// on success. For `PASS_REPL`, [`args`](Self::args) contains the replacement
/// argument list supplied by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationOperationResponse {
    /// Upstream TACACS+ server that handled the request, or a local stub marker.
    pub server: String,
    /// TACACS+ authorization reply status.
    pub status: AuthorizationResponseStatus,
    /// Human-readable message returned by the TACACS+ server or local service.
    pub server_message: String,
    /// Server-modified argument list for `PASS_REPL`.
    pub args: Vec<String>,
}

/// Normalized TACACS+ accounting reply status values.
///
/// These directly correspond to the status octets defined in
/// [RFC 8907 §7.2](https://www.rfc-editor.org/rfc/rfc8907#section-7.2) for the
/// `TAC_PLUS_ACCT` reply body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingResponseStatus {
    /// `TAC_PLUS_ACCT_STATUS_SUCCESS` (`0x01`) — the accounting record was
    /// accepted successfully by the TACACS+ server.
    Success,
    /// `TAC_PLUS_ACCT_STATUS_ERROR` (`0x02`) — the server rejected the
    /// accounting operation or encountered an error processing it.
    Error,
    /// `TAC_PLUS_ACCT_STATUS_FOLLOW` (`0x21`) — the client should continue
    /// with a follow-up action defined by the server deployment.
    Follow,
}

/// Normalized TACACS+ authorization reply status values.
///
/// These directly correspond to the status octets defined in
/// [RFC 8907 §6.2](https://www.rfc-editor.org/rfc/rfc8907#section-6.2) for the
/// `TAC_PLUS_AUTHOR` reply body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationResponseStatus {
    /// `TAC_PLUS_AUTHOR_STATUS_PASS_ADD` (`0x01`) — request is accepted and
    /// returned arguments should be appended.
    PassAdd,
    /// `TAC_PLUS_AUTHOR_STATUS_PASS_REPL` (`0x02`) — request is accepted and
    /// returned arguments replace the submitted arguments.
    PassRepl,
    /// `TAC_PLUS_AUTHOR_STATUS_FAIL` (`0x10`) — authorization is denied.
    Fail,
    /// `TAC_PLUS_AUTHOR_STATUS_ERROR` (`0x11`) — authorization could not be
    /// completed due to an error.
    Error,
    /// `TAC_PLUS_AUTHOR_STATUS_FOLLOW` (`0x21`) — follow-up handling is needed.
    Follow,
}

impl AuthorizationResponseStatus {
    /// Returns the RFC 8907 status code carried in the TACACS+ authorization reply.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tacacsrs_agent_client::AuthorizationResponseStatus;
    /// assert_eq!(AuthorizationResponseStatus::PassAdd.code(), 0x01);
    /// assert_eq!(AuthorizationResponseStatus::PassRepl.code(), 0x02);
    /// assert_eq!(AuthorizationResponseStatus::Fail.code(), 0x10);
    /// assert_eq!(AuthorizationResponseStatus::Error.code(), 0x11);
    /// assert_eq!(AuthorizationResponseStatus::Follow.code(), 0x21);
    /// ```
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::PassAdd => 0x01,
            Self::PassRepl => 0x02,
            Self::Fail => 0x10,
            Self::Error => 0x11,
            Self::Follow => 0x21,
        }
    }

    /// Converts this status into the protobuf `i32` representation.
    fn into_proto(self) -> i32 {
        i32::from(self.code())
    }

    /// Converts a protobuf `i32` status value back into the typed enum.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is out of `u8` range, is the
    /// `UNSPECIFIED` sentinel (`0`), or does not match a known status code.
    fn from_proto(value: i32) -> anyhow::Result<Self> {
        match u8::try_from(value).context("IPC authorization status value is out of u8 range")? {
            0 => bail!("IPC authorization status must not be unspecified"),
            0x01 => Ok(Self::PassAdd),
            0x02 => Ok(Self::PassRepl),
            0x10 => Ok(Self::Fail),
            0x11 => Ok(Self::Error),
            0x21 => Ok(Self::Follow),
            _ => bail!("IPC authorization status value is not recognized"),
        }
    }
}

impl AccountingResponseStatus {
    /// Returns the RFC 8907 status code carried in the TACACS+ accounting reply.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tacacsrs_agent_client::AccountingResponseStatus;
    /// assert_eq!(AccountingResponseStatus::Success.code(), 0x01);
    /// assert_eq!(AccountingResponseStatus::Error.code(), 0x02);
    /// assert_eq!(AccountingResponseStatus::Follow.code(), 0x21);
    /// ```
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0x01,
            Self::Error => 0x02,
            Self::Follow => 0x21,
        }
    }

    /// Converts this status into the protobuf `i32` representation.
    fn into_proto(self) -> i32 {
        i32::from(self.code())
    }

    /// Converts a protobuf `i32` status value back into the typed enum.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is out of `u8` range, is the
    /// `UNSPECIFIED` sentinel (`0`), or does not match a known status code.
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

/// Structured error returned by the local service when a request cannot be
/// fulfilled.
///
/// This type is used on the service side to build error responses and on the
/// client side to interpret them. The [`retriable`](ServiceError::retriable)
/// flag tells callers whether repeating the same request may succeed after the
/// service performs failover or recovery.
///
/// # Builder pattern
///
/// ```
/// # use tacacsrs_agent_client::ServiceError;
/// let error = ServiceError::new("connection reset")
///     .with_server("tacacs-a:49")
///     .retriable(true);
///
/// assert_eq!(error.message, "connection reset");
/// assert_eq!(error.server.as_deref(), Some("tacacs-a:49"));
/// assert!(error.retriable);
/// ```
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
    /// Creates a new service error with the given message.
    ///
    /// The `server` field defaults to `None` and `retriable` defaults to
    /// `false`. Use the builder methods to set them.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            server: None,
            retriable: false,
        }
    }

    /// Associates an upstream server name with this error.
    #[must_use]
    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    /// Sets whether the caller should consider retrying the request.
    #[must_use]
    pub const fn retriable(mut self, retriable: bool) -> Self {
        self.retriable = retriable;
        self
    }

    /// Converts this domain error into its protobuf representation.
    #[must_use]
    pub fn into_proto(self) -> ipc::ServiceError {
        ipc::ServiceError {
            message: self.message,
            server: self.server.unwrap_or_default(),
            retriable: self.retriable,
        }
    }

    /// Converts a protobuf service error into the typed domain error.
    ///
    /// An empty `server` string in the protobuf message is interpreted as
    /// `None` in the domain type (no server was selected when the error
    /// occurred).
    #[must_use]
    pub fn from_proto(proto: ipc::ServiceError) -> Self {
        Self {
            message: proto.message,
            server: (!proto.server.is_empty()).then_some(proto.server),
            retriable: proto.retriable,
        }
    }
}

// ---------------------------------------------------------------------------
// Protobuf ↔ domain conversions for AccountingOperation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Protobuf ↔ domain conversions for AuthorizationOperation
// ---------------------------------------------------------------------------

impl From<AuthorizationOperation> for ipc::AuthorizationRequest {
    fn from(value: AuthorizationOperation) -> Self {
        Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            service: value.service,
            command: value.command,
            command_arguments: value.command_arguments,
            privilege_level: value.privilege_level,
        }
    }
}

impl From<&AuthorizationOperation> for ipc::AuthorizationRequest {
    fn from(value: &AuthorizationOperation) -> Self {
        Self {
            user: value.user.clone(),
            port: value.port.clone(),
            remote_address: value.remote_address.clone(),
            service: value.service.clone(),
            command: value.command.clone(),
            command_arguments: value.command_arguments.clone(),
            privilege_level: value.privilege_level,
        }
    }
}

impl TryFrom<ipc::AuthorizationRequest> for AuthorizationOperation {
    type Error = anyhow::Error;

    fn try_from(value: ipc::AuthorizationRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            service: value.service,
            command: value.command,
            command_arguments: value.command_arguments,
            privilege_level: value.privilege_level,
        })
    }
}

// ---------------------------------------------------------------------------
// Protobuf ↔ domain conversions for AccountingOperationResponse
// ---------------------------------------------------------------------------

impl AccountingOperationResponse {
    /// Converts this domain response into its protobuf representation.
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

// ---------------------------------------------------------------------------
// Protobuf ↔ domain conversions for AuthorizationOperationResponse
// ---------------------------------------------------------------------------

impl AuthorizationOperationResponse {
    /// Converts this domain response into its protobuf representation.
    #[must_use]
    pub fn into_proto(self) -> ipc::AuthorizationResponse {
        ipc::AuthorizationResponse {
            server: self.server,
            status: self.status.into_proto(),
            server_message: self.server_message,
            args: self.args,
        }
    }

    /// Converts a protobuf authorization response into the typed domain response.
    ///
    /// # Errors
    ///
    /// Returns an error if the protobuf status code is missing, out of range, or
    /// not one of the supported TACACS+ authorization reply status values.
    pub fn from_proto(proto: ipc::AuthorizationResponse) -> anyhow::Result<Self> {
        Ok(Self {
            server: proto.server,
            status: AuthorizationResponseStatus::from_proto(proto.status)?,
            server_message: proto.server_message,
            args: proto.args,
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
    fn test_authorization_response_status_codes_match_rfc_values() {
        assert_eq!(AuthorizationResponseStatus::PassAdd.code(), 0x01);
        assert_eq!(AuthorizationResponseStatus::PassRepl.code(), 0x02);
        assert_eq!(AuthorizationResponseStatus::Fail.code(), 0x10);
        assert_eq!(AuthorizationResponseStatus::Error.code(), 0x11);
        assert_eq!(AuthorizationResponseStatus::Follow.code(), 0x21);
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
    fn test_authorization_operation_proto_round_trip() {
        let request = AuthorizationOperation {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            service: "shell".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned()],
            privilege_level: 15,
        };

        let encoded: ipc::AuthorizationRequest = (&request).into();
        let decoded = AuthorizationOperation::try_from(encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn test_authorization_response_proto_round_trip() {
        let response = AuthorizationOperationResponse {
            server: "server-a:49".to_owned(),
            status: AuthorizationResponseStatus::PassRepl,
            server_message: "replace arguments".to_owned(),
            args: vec!["cmd=show".to_owned(), "cmd-arg=users".to_owned()],
        };

        let decoded =
            AuthorizationOperationResponse::from_proto(response.clone().into_proto()).unwrap();
        assert_eq!(decoded, response);
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
