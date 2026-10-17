//! Accounting operation inputs, responses, and reply status.

/// Client-supplied inputs for a TACACS+ accounting operation.
///
/// These fields stay at the RPC level and do not represent the
/// TACACS+ packet header. The service owns header flags, session identifiers,
/// and server selection for the caller.
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
/// +---------------------+                                         +----------+
/// ```
///
/// A failed operation returns a [`crate::failure::ServiceError`] instead of a
/// response. That error carries structured failure facts, not response fields.
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
    /// TACACS+ user name associated with the command.
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
/// Returned after a successful operation. The response includes the upstream server that handled the
/// request and the TACACS+ accounting reply status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingOperationResponse {
    /// Upstream TACACS+ server that handled the request, for example, `"tacacs.corp:49"`.
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

/// Normalized TACACS+ accounting reply status values.
///
/// These directly correspond to the status octets defined in
/// [RFC 8907 §7.2](https://www.rfc-editor.org/rfc/rfc8907#section-7.2) for the
/// `TAC_PLUS_ACCT` reply body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingResponseStatus {
    /// `TAC_PLUS_ACCT_STATUS_SUCCESS` (`0x01`) — the TACACS+ server accepted
    /// the accounting record.
    Success,
    /// `TAC_PLUS_ACCT_STATUS_ERROR` (`0x02`) — the server rejected the
    /// accounting operation or found an error while it processed the operation.
    Error,
    /// `TAC_PLUS_ACCT_STATUS_FOLLOW` (`0x21`) — RFC 8907 recommends treating
    /// this deprecated status as an authentication failure.
    Follow,
}

impl AccountingResponseStatus {
    /// Returns the RFC 8907 status code carried in the TACACS+ accounting reply.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tacacsrs_protocol::operations::AccountingResponseStatus;
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
}
