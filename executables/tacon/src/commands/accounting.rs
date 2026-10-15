//! TACACS+ accounting command support.

use anyhow::Context;
use tacacsrs_protocol::operations::{AccountingOperation, AccountingOperationResponse};

use crate::connection::Connection;

/// Sends a prepared accounting operation over a direct TACACS+ connection.
///
/// # Errors
///
/// Returns an error if the accounting exchange fails.
pub(crate) async fn send_direct(
    connection: &Connection,
    operation: &AccountingOperation,
) -> anyhow::Result<AccountingOperationResponse> {
    let reply = connection
        .execute(operation.exchange())
        .await
        .context("Failed to send accounting request")?;

    Ok(AccountingOperationResponse::from_reply(connection.server_name(), reply))
}

/// Builds an [`AccountingOperation`] from CLI-level arguments.
pub fn accounting_operation(
    user: &str,
    port: &str,
    rem_address: &str,
    cmd: &str,
    cmd_args: Option<&Vec<String>>,
) -> AccountingOperation {
    AccountingOperation {
        user: user.to_owned(),
        port: port.to_owned(),
        remote_address: rem_address.to_owned(),
        command: cmd.to_owned(),
        command_arguments: cmd_args.cloned().unwrap_or_default(),
    }
}

#[cfg(test)]
fn build_accounting_args(cmd: &str, cmd_args: Option<&Vec<String>>) -> Vec<String> {
    accounting_operation("admin", "tty0", "192.0.2.1", cmd, cmd_args)
        .to_request()
        .args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_accounting_args_without_cmd_args() {
        let args = build_accounting_args("show version", None);

        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "service=shell");
        assert_eq!(args[1], "cmd=show version");
    }

    #[test]
    fn test_build_accounting_args_with_cmd_args() {
        let cmd_args = vec!["arg1".to_owned(), "arg2".to_owned()];
        let args = build_accounting_args("configure", Some(&cmd_args));

        assert_eq!(args.len(), 4);
        assert_eq!(args[0], "service=shell");
        assert_eq!(args[1], "cmd=configure");
        assert_eq!(args[2], "cmd-arg=arg1");
        assert_eq!(args[3], "cmd-arg=arg2");
    }

    #[test]
    fn test_build_accounting_args_with_empty_cmd_args() {
        let cmd_args = vec![];
        let args = build_accounting_args("exit", Some(&cmd_args));

        assert_eq!(args.len(), 2);
    }
}
