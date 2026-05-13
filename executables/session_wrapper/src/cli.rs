//! Command line contract for `session-wrapper`.
//!
//! The options model the eventual login-wrapper integration: caller-supplied
//! user identity, TACACS+ context, fail policy, and the command vector to run
//! under supervision.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Determines how the wrapper behaves when TACACS+ authorization cannot be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailPolicy {
    /// Deny the session when authorization cannot be completed.
    Closed,

    /// Allow the session when authorization cannot be completed.
    Open,
}

/// TACACS+ controlled login session wrapper.
#[derive(Debug, Clone, Parser)]
#[command(name = "session-wrapper", version, author)]
#[command(about = "TACACS+ controlled login session wrapper", long_about = None)]
pub struct Cli {
    /// Target username for the wrapped session.
    #[arg(long)]
    pub user: String,

    /// UID to drop to after forking the session process.
    #[arg(long)]
    pub user_uid: libc::uid_t,

    /// GID to drop to after forking the session process.
    #[arg(long)]
    pub user_gid: libc::gid_t,

    /// IPC endpoint for the central TACACS+ client service.
    #[arg(long, default_value = "/run/tacacs.sock", value_name = "PATH_OR_ADDR")]
    pub service_endpoint: String,

    /// Policy to apply when TACACS+ authorization cannot be completed.
    #[arg(long, value_enum, default_value_t = FailPolicy::Closed)]
    pub fail_policy: FailPolicy,

    /// Maximum milliseconds to wait for an authorization IPC reply.
    #[arg(long, default_value_t = 5_000, value_parser = clap::value_parser!(u64).range(1..))]
    pub authorization_timeout_ms: u64,

    /// Current TACACS+ privilege level for the wrapped user (0-15).
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=15))]
    pub privilege_level: u8,

    /// Path to a file listing executables that are always allowed.
    #[arg(long, value_name = "FILE")]
    pub allowlist: Option<PathBuf>,

    /// TACACS+ port context field, typically populated from the SSH environment.
    #[arg(long)]
    pub port: Option<String>,

    /// TACACS+ remote address context field, typically populated from the SSH environment.
    #[arg(long)]
    pub rem_addr: Option<String>,

    /// Increase verbosity level (-v, -vv, -vvv, -vvvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Terminal command and arguments to execute under the wrapped session.
    #[arg(
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND [ARGS]..."
    )]
    pub command: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::{CommandFactory, Parser};

    use super::{Cli, FailPolicy};

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn required_user_identity_and_defaults_parse() {
        let cli = Cli::parse_from([
            "session-wrapper",
            "--user",
            "alice",
            "--user-uid",
            "1000",
            "--user-gid",
            "1000",
            "--",
            "/bin/bash",
        ]);

        assert_eq!(cli.user, "alice");
        assert_eq!(cli.user_uid, 1000);
        assert_eq!(cli.user_gid, 1000);
        assert_eq!(cli.service_endpoint, "/run/tacacs.sock");
        assert_eq!(cli.fail_policy, FailPolicy::Closed);
        assert_eq!(cli.authorization_timeout_ms, 5_000);
        assert_eq!(cli.privilege_level, 1);
        assert_eq!(cli.verbose, 0);
        assert_eq!(cli.command, vec!["/bin/bash".to_owned()]);
    }

    #[test]
    fn optional_context_and_fail_policy_parse() {
        let cli = Cli::parse_from([
            "session-wrapper",
            "--user",
            "bob",
            "--user-uid",
            "1001",
            "--user-gid",
            "1002",
            "--service-endpoint",
            "127.0.0.1:9049",
            "--fail-policy",
            "open",
            "--authorization-timeout-ms",
            "2500",
            "--privilege-level",
            "15",
            "--allowlist",
            "/etc/session-wrapper.allow",
            "--port",
            "ssh",
            "--rem-addr",
            "192.0.2.10",
            "-vv",
            "--",
            "show",
            "version",
        ]);

        assert_eq!(cli.service_endpoint, "127.0.0.1:9049");
        assert_eq!(cli.fail_policy, FailPolicy::Open);
        assert_eq!(cli.authorization_timeout_ms, 2_500);
        assert_eq!(cli.privilege_level, 15);
        assert_eq!(cli.allowlist, Some(PathBuf::from("/etc/session-wrapper.allow")));
        assert_eq!(cli.port.as_deref(), Some("ssh"));
        assert_eq!(cli.rem_addr.as_deref(), Some("192.0.2.10"));
        assert_eq!(cli.verbose, 2);
        assert_eq!(cli.command, vec!["show".to_owned(), "version".to_owned()]);
    }

    #[test]
    fn user_is_required() {
        let error = Cli::try_parse_from([
            "session-wrapper",
            "--user-uid",
            "1000",
            "--user-gid",
            "1000",
            "--",
            "/bin/bash",
        ])
        .expect_err("missing user should fail");

        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn command_is_required() {
        let error = Cli::try_parse_from([
            "session-wrapper",
            "--user",
            "alice",
            "--user-uid",
            "1000",
            "--user-gid",
            "1000",
        ])
        .expect_err("missing command should fail");

        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
