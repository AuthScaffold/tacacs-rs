//! Transport-independent request and response types for the local IPC API.
//!
//! The protocol deliberately models TACACS+ operations rather than raw packet
//! headers so local callers can issue accounting requests without having to
//! understand TACACS+ framing details. The schema generated from these types is
//! checked into the repository and validated in tests.
//!
//! Maintainability note: the Rust types in this module are the source of truth.
//! The checked-in JSON schema exists so non-Rust consumers can inspect the
//! contract in GitHub, while the schema-matching test ensures the repository
//! does not drift out of sync. For this small internal IPC contract, that is a
//! lower-maintenance choice than introducing a schema-first code generation
//! pipeline.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Top-level IPC request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ServiceRequest {
    /// Execute a single TACACS+ accounting transaction.
    Accounting(AccountingOperation),
}

/// Top-level IPC response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "result", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ServiceResponse {
    /// Successful TACACS+ accounting reply from the selected upstream server.
    Accounting(AccountingOperationResponse),
    /// Service-side or upstream failure information.
    Error(ServiceError),
}

/// Client-supplied inputs for a TACACS+ accounting operation.
///
/// These fields intentionally stay at the RPC level instead of mirroring the
/// TACACS+ packet header. The service owns header flags, session identifiers,
/// and server selection on behalf of the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub command_arguments: Vec<String>,
}

/// RFC-aware service response for a TACACS+ accounting operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
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
}

/// Structured error returned by the local service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceError {
    /// Error text suitable for logs and operator-facing diagnostics.
    pub message: String,
    /// Upstream server associated with the error, if one had already been chosen.
    pub server: Option<String>,
    /// Whether retrying against the service may succeed after failover or recovery.
    #[serde(default)]
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
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use schemars::schema_for;
    use serde_json::json;

    use super::*;

    #[allow(dead_code)]
    #[derive(JsonSchema)]
    struct ServiceProtocolSchemaDocument {
        request: ServiceRequest,
        response: ServiceResponse,
    }

    fn protocol_schema_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ipc-protocol.schema.json")
    }

    fn generated_schema() -> serde_json::Value {
        schema_for!(ServiceProtocolSchemaDocument).to_value()
    }

    #[test]
    fn test_checked_in_schema_matches_protocol_types() {
        let expected: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(protocol_schema_path()).expect("schema file should exist"),
        )
        .expect("schema file should be valid json");

        assert_eq!(generated_schema(), expected);
    }

    #[test]
    fn test_accounting_operation_rejects_unknown_fields() {
        let invalid_request = json!({
            "operation": "accounting",
            "user": "admin",
            "port": "tty0",
            "remote_address": "127.0.0.1",
            "command": "show",
            "command_arguments": ["users"],
            "custom_flag_1": true,
            "session_id": 42
        });

        let error =
            serde_json::from_value::<ServiceRequest>(invalid_request).expect_err("must reject");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn test_accounting_response_status_codes_match_rfc_values() {
        assert_eq!(AccountingResponseStatus::Success.code(), 0x01);
        assert_eq!(AccountingResponseStatus::Error.code(), 0x02);
        assert_eq!(AccountingResponseStatus::Follow.code(), 0x21);
    }
}
