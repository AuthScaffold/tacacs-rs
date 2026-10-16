//! Authorization operation inputs, responses, reply status, and auth context.

use anyhow::{Context, bail};

use crate::privilege::PrivilegeLevel;

use super::arguments::{AuthorizationArg, AuthorizationKey, AuthorizationRequestBuilder};

/// Authentication metadata asserted by an authorization operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationAuthenticationContext {
    TacacsAscii,
    TacacsPap,
    Unauthenticated,
}

/// Client-supplied inputs for a TACACS+ authorization operation.
///
/// Local command mediation code uses this IPC contract. The fixed fields
/// represent the TACACS+ Authorization REQUEST header context. [`args`](Self::args)
/// contains the ordered RFC 8907 §8.2 authorization argument-value pairs. These
/// pairs include `service`, `cmd`, `cmd-arg`, and `priv-lvl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationOperation {
    /// TACACS+ user name associated with the command.
    pub user: String,
    /// NAS or tty/port identifier reported to the TACACS+ server.
    pub port: String,
    /// Remote client address to report in the TACACS+ authorization request.
    pub remote_address: String,
    /// TACACS+ privilege level for the command context.
    pub privilege_level: PrivilegeLevel,
    /// How the user identity was authenticated before authorization.
    pub authentication_context: AuthorizationAuthenticationContext,
    /// Ordered TACACS+ authorization argument-value pairs.
    pub args: Vec<AuthorizationArg>,
}

impl AuthorizationOperation {
    /// Creates a builder for an authorization operation.
    #[must_use]
    pub fn builder(
        user: impl Into<String>,
        privilege_level: u32,
        authentication_context: AuthorizationAuthenticationContext,
    ) -> AuthorizationRequestBuilder {
        AuthorizationRequestBuilder::new(user, privilege_level, authentication_context)
    }

    /// Returns all values for a well-known authorization key, preserving order.
    pub fn values(&self, key: AuthorizationKey) -> impl Iterator<Item = &str> {
        self.args
            .iter()
            .filter(move |arg| arg.name == key.as_str())
            .map(|arg| arg.value.as_str())
    }

    /// Returns the first value for a well-known authorization key.
    #[must_use]
    pub fn first_value(&self, key: AuthorizationKey) -> Option<&str> {
        self.values(key).next()
    }

    /// Returns the request service, if present.
    #[must_use]
    pub fn service(&self) -> Option<&str> {
        self.first_value(AuthorizationKey::Service)
    }

    /// Returns the shell command value, if present.
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.first_value(AuthorizationKey::Cmd)
    }

    /// Returns command arguments in their RFC-defined order.
    pub fn command_arguments(&self) -> impl Iterator<Item = &str> {
        self.values(AuthorizationKey::CmdArg)
    }

    /// Makes sure that the request has the RFC-required authorization arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if `service` is missing, or if `service=shell` is used
    /// without a `cmd` argument.
    pub fn validate(&self) -> anyhow::Result<()> {
        for arg in &self.args {
            arg.validate()?;
        }
        let service = self
            .service()
            .context("authorization request requires service key")?;
        if service == "shell" && self.command().is_none() {
            bail!("authorization request with service='shell' requires cmd key");
        }
        Ok(())
    }
}

/// RFC-aware service response for a TACACS+ authorization operation.
///
/// Returned after a successful operation. For `PASS_ADD`, [`args`](Self::args) contains the server
/// arguments to merge as RFC 8907 §6.2 specifies. For `PASS_REPL`, these
/// arguments replace all request arguments. The field is empty if the server
/// returned `arg_cnt = 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationOperationResponse {
    /// Upstream TACACS+ server that handled the request, or a local stub marker.
    pub server: String,
    /// TACACS+ authorization reply status.
    pub status: AuthorizationResponseStatus,
    /// Human-readable message returned by the TACACS+ server or local service.
    pub server_message: String,
    /// Server argument-value pairs for `PASS_ADD` and `PASS_REPL`.
    ///
    /// The field is empty if the server returned `arg_cnt = 0`.
    pub args: Vec<AuthorizationArg>,
    /// Client-specific display or log data returned by the TACACS+ server.
    pub data: String,
}

/// Normalized TACACS+ authorization reply status values.
///
/// These directly correspond to the status octets defined in
/// [RFC 8907 §6.2](https://www.rfc-editor.org/rfc/rfc8907#section-6.2) for the
/// `TAC_PLUS_AUTHOR` reply body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationResponseStatus {
    /// `TAC_PLUS_AUTHOR_STATUS_PASS_ADD` (`0x01`) — the request is accepted.
    /// The client must append the returned arguments.
    PassAdd,
    /// `TAC_PLUS_AUTHOR_STATUS_PASS_REPL` (`0x02`) — request is accepted and
    /// returned arguments replace the submitted arguments.
    PassRepl,
    /// `TAC_PLUS_AUTHOR_STATUS_FAIL` (`0x10`) — authorization is denied.
    Fail,
    /// `TAC_PLUS_AUTHOR_STATUS_ERROR` (`0x11`) — an error prevented authorization.
    Error,
    /// `TAC_PLUS_AUTHOR_STATUS_FOLLOW` (`0x21`) — RFC 8907 recommends treating
    /// this deprecated status as an authentication failure.
    Follow,
}

impl AuthorizationResponseStatus {
    /// Returns the RFC 8907 status code carried in the TACACS+ authorization reply.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tacacsrs_protocol::operations::AuthorizationResponseStatus;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_response_status_codes_match_rfc_values() {
        assert_eq!(AuthorizationResponseStatus::PassAdd.code(), 0x01);
        assert_eq!(AuthorizationResponseStatus::PassRepl.code(), 0x02);
        assert_eq!(AuthorizationResponseStatus::Fail.code(), 0x10);
        assert_eq!(AuthorizationResponseStatus::Error.code(), 0x11);
        assert_eq!(AuthorizationResponseStatus::Follow.code(), 0x21);
    }
}
