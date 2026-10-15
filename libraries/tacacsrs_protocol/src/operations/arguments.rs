//! Authorization argument-value pairs, the well-known key dictionary, and the
//! request builder.

use std::str::FromStr;

use anyhow::bail;

use crate::privilege::PrivilegeLevel;

use super::authorization::{AuthorizationAuthenticationContext, AuthorizationOperation};

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
            privilege_level: PrivilegeLevel::try_from(self.privilege_level)?,
            authentication_context: self.authentication_context,
            args: self.args,
        };
        operation.validate()?;
        Ok(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
