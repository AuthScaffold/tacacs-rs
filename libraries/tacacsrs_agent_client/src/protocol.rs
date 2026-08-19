//! Domain-level request and response types for the local TACACS+ client API.
//!
//! Protobuf defines the local IPC transport, which gRPC serves. The rest of the
//! crate uses operation-specific Rust types. Thus, callers do not depend
//! directly on generated transport code.
//!
//! # Design rationale
//!
//! These types represent the **logical operation**, not the
//! TACACS+ packet layout. The service owns header flags, session identifiers,
//! and server selection for the caller. The client API does not change when the
//! underlying TACACS+ encoding changes.
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

use std::str::FromStr;

use anyhow::{Context, bail};
use tacacsrs_secrets::SecretBytes;

use crate::ipc;

/// Client-supplied inputs for one fixed PAP authentication operation.
#[derive(Debug, Clone)]
pub struct PapAuthenticationOperation {
    pub user: String,
    pub password: SecretBytes,
    pub port: String,
    pub remote_address: String,
    pub privilege_level: u32,
}

/// Successful PAP authentication response from an upstream TACACS+ server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PapAuthenticationOperationResponse {
    pub server: String,
    pub status: AuthenticationResponseStatus,
    pub server_message: String,
    pub data: Vec<u8>,
}

/// Terminal statuses valid for an RFC 8907 PAP exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationResponseStatus {
    Pass,
    Fail,
    Error,
}

/// Authentication metadata asserted by an authorization operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationAuthenticationContext {
    TacacsAscii,
    TacacsPap,
    Unauthenticated,
}

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
/// Returned by [`ServiceClient::send_accounting`](crate::ServiceClient::send_accounting)
/// on success. The response includes the upstream server that handled the
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
    pub privilege_level: u32,
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
        if self.privilege_level > 15 {
            bail!(
                "authorization privilege level {} is outside the TACACS+ range 0-15",
                self.privilege_level
            );
        }
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

/// One TACACS+ authorization argument-value pair from the server.
///
/// RFC 8907 §6.1 encodes authorization arguments as strings of the form
/// `name=value` (mandatory) or `name*value` (optional). This struct decodes
/// that encoding so callers can make policy decisions without re-parsing raw
/// strings.
///
/// # Mandatory vs optional
///
/// - `mandatory = true` (`=` separator) — the receiving side **MUST** handle
///   the argument, or treat the authorization as failed.
/// - `mandatory = false` (`*` separator) — the receiving side **MAY** ignore
///   the argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationArg {
    /// Argument name, for example, `"priv-lvl"`, `"cmd"`, or `"service"`.
    pub name: String,
    /// `true` when the original separator was `=` (mandatory).
    /// `false` when the original separator was `*` (optional).
    pub mandatory: bool,
    /// Argument value (everything after the first separator in the wire string).
    pub value: String,
}

impl AuthorizationArg {
    /// Creates a TACACS+ authorization argument-value pair.
    #[must_use]
    pub fn new(name: impl Into<String>, mandatory: bool, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mandatory,
            value: value.into(),
        }
    }

    /// Creates a mandatory TACACS+ argument (`name=value`).
    #[must_use]
    pub fn mandatory(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, true, value)
    }

    /// Creates an optional TACACS+ argument (`name*value`).
    #[must_use]
    pub fn optional(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, false, value)
    }

    /// Creates a mandatory TACACS+ argument from a well-known key.
    #[must_use]
    pub fn mandatory_key(key: AuthorizationKey, value: impl Into<String>) -> Self {
        Self::mandatory(key.as_str(), value)
    }

    /// Creates an optional TACACS+ argument from a well-known key.
    #[must_use]
    pub fn optional_key(key: AuthorizationKey, value: impl Into<String>) -> Self {
        Self::optional(key.as_str(), value)
    }

    /// Parses this argument name as a well-known RFC 8907 §8.2 key.
    #[must_use]
    pub fn well_known_key(&self) -> Option<AuthorizationKey> {
        AuthorizationKey::from_str(&self.name).ok()
    }

    /// Makes sure that this argument-value pair is valid for the IPC boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is empty or contains TACACS+ separators.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("authorization argument has an empty name");
        }
        if self.name.contains('=') || self.name.contains('*') {
            anyhow::bail!(
                "authorization argument name {:?} contains a separator ('=' or '*')",
                self.name
            );
        }
        Ok(())
    }

    /// Parses a raw TACACS+ argument-value string into an [`AuthorizationArg`].
    ///
    /// The separator is the first `=` or `*` found in the string. If both are
    /// present, whichever appears first determines the separator. The name is
    /// everything before the separator; the value is everything after.
    ///
    /// # Errors
    ///
    /// Returns an error if the string contains neither `=` nor `*`.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let eq_pos = raw.find('=');
        let ast_pos = raw.find('*');
        let (sep_pos, mandatory) = match (eq_pos, ast_pos) {
            (Some(e), Some(a)) => {
                if e < a {
                    (e, true)
                } else {
                    (a, false)
                }
            }
            (Some(e), None) => (e, true),
            (None, Some(a)) => (a, false),
            (None, None) => {
                anyhow::bail!("authorization argument {raw:?} has no separator ('=' or '*')")
            }
        };
        let arg = Self {
            name: raw[..sep_pos].to_owned(),
            mandatory,
            value: raw[sep_pos + 1..].to_owned(),
        };
        arg.validate()?;
        Ok(arg)
    }
}

/// RFC 8907 §8.2 well-known TACACS+ authorization argument names.
///
/// This enum documents the standard argument dictionary and provides a typed
/// alternative to repeating string literals across callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorizationKey {
    Service,
    Protocol,
    Cmd,
    CmdArg,
    Acl,
    InAcl,
    OutAcl,
    Addr,
    AddrPool,
    Timeout,
    IdleTime,
    AutoCmd,
    NoEscape,
    NoHangup,
    PrivLvl,
}

impl AuthorizationKey {
    /// Returns the RFC string name for this authorization key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Protocol => "protocol",
            Self::Cmd => "cmd",
            Self::CmdArg => "cmd-arg",
            Self::Acl => "acl",
            Self::InAcl => "inacl",
            Self::OutAcl => "outacl",
            Self::Addr => "addr",
            Self::AddrPool => "addr-pool",
            Self::Timeout => "timeout",
            Self::IdleTime => "idletime",
            Self::AutoCmd => "autocmd",
            Self::NoEscape => "noescape",
            Self::NoHangup => "nohangup",
            Self::PrivLvl => "priv-lvl",
        }
    }
}

impl FromStr for AuthorizationKey {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "service" => Ok(Self::Service),
            "protocol" => Ok(Self::Protocol),
            "cmd" => Ok(Self::Cmd),
            "cmd-arg" => Ok(Self::CmdArg),
            "acl" => Ok(Self::Acl),
            "inacl" => Ok(Self::InAcl),
            "outacl" => Ok(Self::OutAcl),
            "addr" => Ok(Self::Addr),
            "addr-pool" => Ok(Self::AddrPool),
            "timeout" => Ok(Self::Timeout),
            "idletime" => Ok(Self::IdleTime),
            "autocmd" => Ok(Self::AutoCmd),
            "noescape" => Ok(Self::NoEscape),
            "nohangup" => Ok(Self::NoHangup),
            "priv-lvl" => Ok(Self::PrivLvl),
            _ => bail!("unrecognized authorization key {value:?}"),
        }
    }
}

/// Builder for an [`AuthorizationOperation`] that uses RFC argument-value pairs.
#[derive(Debug, Clone)]
pub struct AuthorizationRequestBuilder {
    user: String,
    port: String,
    remote_address: String,
    privilege_level: u32,
    authentication_context: AuthorizationAuthenticationContext,
    args: Vec<AuthorizationArg>,
}

impl AuthorizationRequestBuilder {
    /// Creates a new authorization request builder.
    #[must_use]
    pub fn new(
        user: impl Into<String>,
        privilege_level: u32,
        authentication_context: AuthorizationAuthenticationContext,
    ) -> Self {
        Self {
            user: user.into(),
            port: String::new(),
            remote_address: String::new(),
            privilege_level,
            authentication_context,
            args: Vec::new(),
        }
    }

    /// Sets the request port value.
    #[must_use]
    pub fn port(mut self, port: impl Into<String>) -> Self {
        self.port = port.into();
        self
    }

    /// Sets the request remote-address value.
    #[must_use]
    pub fn remote_address(mut self, remote_address: impl Into<String>) -> Self {
        self.remote_address = remote_address.into();
        self
    }

    /// Adds one authorization argument-value pair.
    #[must_use]
    pub fn arg(mut self, arg: AuthorizationArg) -> Self {
        self.args.push(arg);
        self
    }

    /// Adds one authorization argument-value pair with a typed key.
    #[must_use]
    pub fn key_value(
        self,
        key: AuthorizationKey,
        mandatory: bool,
        value: impl Into<String>,
    ) -> Self {
        self.arg(AuthorizationArg::new(key.as_str(), mandatory, value))
    }

    /// Adds a mandatory `service` key.
    #[must_use]
    pub fn service(self, value: impl Into<String>) -> Self {
        self.key_value(AuthorizationKey::Service, true, value)
    }

    /// Adds a mandatory `cmd` key.
    #[must_use]
    pub fn command(self, value: impl Into<String>) -> Self {
        self.key_value(AuthorizationKey::Cmd, true, value)
    }

    /// Adds a mandatory `cmd-arg` key in request order.
    #[must_use]
    pub fn command_arg(self, value: impl Into<String>) -> Self {
        self.key_value(AuthorizationKey::CmdArg, true, value)
    }

    /// Adds mandatory `cmd-arg` keys in request order.
    #[must_use]
    pub fn command_args<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for value in values {
            self = self.command_arg(value);
        }
        self
    }

    /// Adds an optional `protocol` key.
    #[must_use]
    pub fn protocol(self, value: impl Into<String>) -> Self {
        self.key_value(AuthorizationKey::Protocol, false, value)
    }

    /// Adds a mandatory `priv-lvl` argument-value pair.
    #[must_use]
    pub fn assigned_privilege_level(self, value: u8) -> Self {
        self.key_value(AuthorizationKey::PrivLvl, true, value.to_string())
    }

    /// Adds a mandatory `timeout` key, in minutes.
    #[must_use]
    pub fn timeout_minutes(self, value: u32) -> Self {
        self.key_value(AuthorizationKey::Timeout, true, value.to_string())
    }

    /// Adds a mandatory `idletime` key, in minutes.
    #[must_use]
    pub fn idle_time_minutes(self, value: u32) -> Self {
        self.key_value(AuthorizationKey::IdleTime, true, value.to_string())
    }

    /// Adds a mandatory `autocmd` key.
    #[must_use]
    pub fn auto_command(self, value: impl Into<String>) -> Self {
        self.key_value(AuthorizationKey::AutoCmd, true, value)
    }

    /// Adds a mandatory `noescape` key.
    #[must_use]
    pub fn no_escape(self, value: bool) -> Self {
        self.key_value(AuthorizationKey::NoEscape, true, value.to_string())
    }

    /// Adds a mandatory `nohangup` key.
    #[must_use]
    pub fn no_hangup(self, value: bool) -> Self {
        self.key_value(AuthorizationKey::NoHangup, true, value.to_string())
    }

    /// Builds a typed authorization operation from the argument-value pairs.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no `service` argument. It also returns an
    /// error if `service` is `shell` and there is no `cmd` argument.
    pub fn build(self) -> anyhow::Result<AuthorizationOperation> {
        let operation = AuthorizationOperation {
            user: self.user,
            port: self.port,
            remote_address: self.remote_address,
            privilege_level: self.privilege_level,
            authentication_context: self.authentication_context,
            args: self.args,
        };
        operation.validate()?;
        Ok(operation)
    }
}

/// RFC-aware service response for a TACACS+ authorization operation.
///
/// Returned by [`ServiceClient::send_authorization`](crate::ServiceClient::send_authorization)
/// on success. For `PASS_ADD`, [`args`](Self::args) contains the server
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
    /// Returns an error if the value is outside the `u8` range. It also returns
    /// an error for the `UNSPECIFIED` sentinel (`0`) or an unknown status code.
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
    /// Returns an error if the value is outside the `u8` range. It also returns
    /// an error for the `UNSPECIFIED` sentinel (`0`) or an unknown status code.
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

impl AuthenticationResponseStatus {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Pass => 0x01,
            Self::Fail => 0x02,
            Self::Error => 0x07,
        }
    }

    fn into_proto(self) -> i32 {
        i32::from(self.code())
    }

    fn from_proto(value: i32) -> anyhow::Result<Self> {
        match u8::try_from(value).context("IPC authentication status value is out of u8 range")? {
            0 => bail!("IPC authentication status must not be unspecified"),
            0x01 => Ok(Self::Pass),
            0x02 => Ok(Self::Fail),
            0x07 => Ok(Self::Error),
            _ => bail!("IPC authentication status value is not recognized"),
        }
    }
}

impl AuthorizationAuthenticationContext {
    const fn into_proto(self) -> i32 {
        match self {
            Self::TacacsAscii => 1,
            Self::TacacsPap => 2,
            Self::Unauthenticated => 3,
        }
    }

    fn from_proto(value: i32) -> anyhow::Result<Self> {
        match value {
            0 => bail!("IPC authorization authentication context must not be unspecified"),
            1 => Ok(Self::TacacsAscii),
            2 => Ok(Self::TacacsPap),
            3 => Ok(Self::Unauthenticated),
            _ => bail!("IPC authorization authentication context is not recognized"),
        }
    }
}

/// Structured error returned by the local service when a request cannot be
/// fulfilled.
///
/// The service uses this type to build error responses. The client uses it to
/// interpret those responses. The [`retriable`](ServiceError::retriable) flag
/// shows if the request can succeed after service failover or recovery.
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
    /// Upstream server associated with the error, if the service selected one.
    pub server: Option<String>,
    /// Whether retrying against the service can succeed after failover or recovery.
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

    /// Sets whether the caller can retry the request.
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
    /// An empty protobuf `server` string becomes `None` in the domain type. This
    /// value means that the service did not select a server.
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

impl From<PapAuthenticationOperation> for ipc::PapAuthenticationRequest {
    fn from(value: PapAuthenticationOperation) -> Self {
        Self {
            user: value.user,
            password: value.password.into_unprotected_vec(),
            port: value.port,
            remote_address: value.remote_address,
            privilege_level: value.privilege_level,
        }
    }
}

impl TryFrom<ipc::PapAuthenticationRequest> for PapAuthenticationOperation {
    type Error = anyhow::Error;

    fn try_from(value: ipc::PapAuthenticationRequest) -> Result<Self, Self::Error> {
        if value.user.is_empty() {
            bail!("PAP authentication requires a user name");
        }
        if value.privilege_level > 15 {
            bail!("PAP authentication privilege level is outside the TACACS+ range 0-15");
        }
        Ok(Self {
            user: value.user,
            password: SecretBytes::new(value.password),
            port: value.port,
            remote_address: value.remote_address,
            privilege_level: value.privilege_level,
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
            privilege_level: value.privilege_level,
            authentication_context: value.authentication_context.into_proto(),
            args: value
                .args
                .into_iter()
                .map(ipc::AuthorizationArg::from)
                .collect(),
        }
    }
}

impl From<&AuthorizationOperation> for ipc::AuthorizationRequest {
    fn from(value: &AuthorizationOperation) -> Self {
        Self {
            user: value.user.clone(),
            port: value.port.clone(),
            remote_address: value.remote_address.clone(),
            privilege_level: value.privilege_level,
            authentication_context: value.authentication_context.into_proto(),
            args: value
                .args
                .iter()
                .cloned()
                .map(ipc::AuthorizationArg::from)
                .collect(),
        }
    }
}

impl TryFrom<ipc::AuthorizationRequest> for AuthorizationOperation {
    type Error = anyhow::Error;

    fn try_from(value: ipc::AuthorizationRequest) -> Result<Self, Self::Error> {
        let operation = Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            privilege_level: value.privilege_level,
            authentication_context: AuthorizationAuthenticationContext::from_proto(
                value.authentication_context,
            )?,
            args: value.args.into_iter().map(AuthorizationArg::from).collect(),
        };
        operation.validate()?;
        Ok(operation)
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
    /// Returns an error if the protobuf status code is missing or outside its
    /// range. It also returns an error for an unsupported TACACS+ accounting
    /// reply status.
    pub fn from_proto(proto: ipc::AccountingResponse) -> anyhow::Result<Self> {
        Ok(Self {
            server: proto.server,
            status: AccountingResponseStatus::from_proto(proto.status)?,
            server_message: proto.server_message,
            data: proto.data,
        })
    }
}

impl PapAuthenticationOperationResponse {
    #[must_use]
    pub fn into_proto(self) -> ipc::PapAuthenticationResponse {
        ipc::PapAuthenticationResponse {
            server: self.server,
            status: self.status.into_proto(),
            server_message: self.server_message,
            data: self.data,
        }
    }

    /// Decodes a protobuf PAP response.
    ///
    /// # Errors
    ///
    /// Returns an error when the status is unspecified or not a terminal PAP
    /// status recognized by the domain contract.
    pub fn from_proto(proto: ipc::PapAuthenticationResponse) -> anyhow::Result<Self> {
        Ok(Self {
            server: proto.server,
            status: AuthenticationResponseStatus::from_proto(proto.status)?,
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
            args: self
                .args
                .into_iter()
                .map(ipc::AuthorizationArg::from)
                .collect(),
            data: self.data,
        }
    }

    /// Converts a protobuf authorization response into the typed domain response.
    ///
    /// # Errors
    ///
    /// Returns an error if the protobuf status code is missing or outside its
    /// range. It also returns an error for an unsupported TACACS+ authorization
    /// reply status or a malformed argument-value pair.
    pub fn from_proto(proto: ipc::AuthorizationResponse) -> anyhow::Result<Self> {
        let response = Self {
            server: proto.server,
            status: AuthorizationResponseStatus::from_proto(proto.status)?,
            server_message: proto.server_message,
            args: proto.args.into_iter().map(AuthorizationArg::from).collect(),
            data: proto.data,
        };
        for arg in &response.args {
            arg.validate()?;
        }
        Ok(response)
    }
}

impl From<AuthorizationArg> for ipc::AuthorizationArg {
    fn from(arg: AuthorizationArg) -> Self {
        Self {
            name: arg.name,
            mandatory: arg.mandatory,
            value: arg.value,
        }
    }
}

impl From<ipc::AuthorizationArg> for AuthorizationArg {
    fn from(arg: ipc::AuthorizationArg) -> Self {
        Self {
            name: arg.name,
            mandatory: arg.mandatory,
            value: arg.value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pap_authentication_proto_round_trip_redacts_password() {
        let request = PapAuthenticationOperation {
            user: "admin".to_owned(),
            password: SecretBytes::new(b"sentinel-secret".to_vec()),
            port: "tty0".to_owned(),
            remote_address: "192.0.2.1".to_owned(),
            privilege_level: 15,
        };
        assert!(!format!("{request:?}").contains("sentinel-secret"));

        let proto = ipc::PapAuthenticationRequest::from(request);
        let decoded = PapAuthenticationOperation::try_from(proto).unwrap();
        assert_eq!(decoded.user, "admin");
        assert_eq!(decoded.password.expose_secret(), b"sentinel-secret");
        assert_eq!(decoded.privilege_level, 15);
    }

    #[test]
    fn pap_authentication_response_proto_round_trip() {
        let response = PapAuthenticationOperationResponse {
            server: "server:49".to_owned(),
            status: AuthenticationResponseStatus::Pass,
            server_message: "ok".to_owned(),
            data: vec![1, 2],
        };
        let decoded =
            PapAuthenticationOperationResponse::from_proto(response.into_proto()).unwrap();
        assert_eq!(decoded.status, AuthenticationResponseStatus::Pass);
        assert_eq!(decoded.data, vec![1, 2]);
    }

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
        let request = AuthorizationOperation::builder(
            "admin",
            15,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .port("tty0")
        .remote_address("127.0.0.1")
        .service("shell")
        .command("show")
        .command_args(vec!["users".to_owned()])
        .build()
        .unwrap();

        let encoded: ipc::AuthorizationRequest = (&request).into();
        let decoded = AuthorizationOperation::try_from(encoded).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.service(), Some("shell"));
        assert_eq!(decoded.command(), Some("show"));
        assert_eq!(decoded.command_arguments().collect::<Vec<_>>(), vec!["users"]);
    }

    #[test]
    fn test_authorization_builder_adds_command_args_in_order() {
        let request = AuthorizationOperation::builder(
            "admin",
            15,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .service("shell")
        .command("show")
        .command_args(vec!["interfaces".to_owned(), "status".to_owned()])
        .build()
        .unwrap();

        assert_eq!(request.command_arguments().collect::<Vec<_>>(), vec!["interfaces", "status"]);
    }

    #[test]
    fn test_authorization_arg_parse_and_key_helpers() {
        let mandatory = AuthorizationArg::parse("priv-lvl=15").unwrap();
        assert_eq!(mandatory.well_known_key(), Some(AuthorizationKey::PrivLvl));
        assert!(mandatory.mandatory);
        assert_eq!(mandatory.value, "15");

        let empty_value = AuthorizationArg::parse("cmd=").unwrap();
        assert_eq!(empty_value.name, "cmd");
        assert!(empty_value.mandatory);
        assert_eq!(empty_value.value, "");

        let optional = AuthorizationArg::parse("protocol*ssh").unwrap();
        assert_eq!(optional.well_known_key(), Some(AuthorizationKey::Protocol));
        assert!(!optional.mandatory);
        assert_eq!(optional.value, "ssh");
    }

    #[test]
    fn test_authorization_arg_parse_rejects_empty_name() {
        let mandatory_error = AuthorizationArg::parse("=15").unwrap_err();
        assert!(mandatory_error.to_string().contains("empty name"));

        let optional_error = AuthorizationArg::parse("*ssh").unwrap_err();
        assert!(optional_error.to_string().contains("empty name"));
    }

    #[test]
    fn test_authorization_arg_validate_rejects_separator_in_name() {
        let error = AuthorizationArg::mandatory("bad=name", "value")
            .validate()
            .unwrap_err();
        assert!(error.to_string().contains("contains a separator"));
    }

    #[test]
    fn test_authorization_operation_rejects_invalid_proto_arg_name() {
        let request = ipc::AuthorizationRequest {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            privilege_level: 15,
            authentication_context: AuthorizationAuthenticationContext::TacacsAscii.into_proto(),
            args: vec![
                ipc::AuthorizationArg {
                    name: "service".to_owned(),
                    mandatory: true,
                    value: "shell".to_owned(),
                },
                ipc::AuthorizationArg {
                    name: "cmd".to_owned(),
                    mandatory: true,
                    value: "show".to_owned(),
                },
                ipc::AuthorizationArg {
                    name: "bad=name".to_owned(),
                    mandatory: true,
                    value: "value".to_owned(),
                },
            ],
        };

        let error = AuthorizationOperation::try_from(request).unwrap_err();
        assert!(error.to_string().contains("contains a separator"));
    }

    #[test]
    fn test_authorization_builder_rejects_privilege_level_above_max() {
        let error = AuthorizationOperation::builder(
            "admin",
            16,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .service("shell")
        .command("show")
        .build()
        .unwrap_err();
        assert!(error.to_string().contains("range 0-15"));
    }

    #[test]
    fn test_authorization_builder_rejects_shell_without_cmd() {
        let error = AuthorizationOperation::builder(
            "admin",
            15,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .service("shell")
        .build()
        .unwrap_err();
        assert!(error.to_string().contains("requires cmd"));
    }

    #[test]
    fn test_authorization_response_proto_round_trip() {
        let response = AuthorizationOperationResponse {
            server: "server-a:49".to_owned(),
            status: AuthorizationResponseStatus::PassRepl,
            server_message: "replace arguments".to_owned(),
            args: vec![
                AuthorizationArg {
                    name: "cmd".to_owned(),
                    mandatory: true,
                    value: "show".to_owned(),
                },
                AuthorizationArg {
                    name: "cmd-arg".to_owned(),
                    mandatory: true,
                    value: "users".to_owned(),
                },
            ],
            data: "display this".to_owned(),
        };

        let decoded =
            AuthorizationOperationResponse::from_proto(response.clone().into_proto()).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn test_authorization_response_rejects_invalid_proto_arg_name() {
        let response = ipc::AuthorizationResponse {
            server: "server-a:49".to_owned(),
            status: AuthorizationResponseStatus::PassAdd.into_proto(),
            server_message: String::new(),
            args: vec![ipc::AuthorizationArg {
                name: "bad*name".to_owned(),
                mandatory: false,
                value: "value".to_owned(),
            }],
            data: String::new(),
        };

        let error = AuthorizationOperationResponse::from_proto(response).unwrap_err();
        assert!(error.to_string().contains("contains a separator"));
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
