//! TACACS+ Accounting command implementation

use anyhow::Context;
use tacacsrs_messages::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_flows::accounting::AccountingExchange;

use crate::connection::Connection;

/// Sends an accounting request to record a command run.
///
/// # Arguments
///
/// * `connection` - The connection used to send this accounting exchange
/// * `user` - Username that runs the command
/// * `port` - Port identifier (for example, "tty0")
/// * `rem_address` - Remote address of the client
/// * `cmd` - The command that the user runs
/// * `cmd_args` - Optional arguments to the command
///
/// # Returns
///
/// The accounting reply from the server, or an error if the request failed.
pub async fn send_accounting_request(
    connection: &Connection,
    user: &str,
    port: &str,
    rem_address: &str,
    cmd: &str,
    cmd_args: Option<&Vec<String>>,
) -> anyhow::Result<AccountingReply> {
    let request = build_accounting_request(user, port, rem_address, cmd, cmd_args);

    let response = connection
        .execute(AccountingExchange::new(request))
        .await
        .context("Failed to send accounting request")?;

    log::info!("Received accounting response: {response:?}");

    Ok(response)
}

/// Constructs an [`AccountingRequest`] from CLI-level arguments.
pub fn build_accounting_request(
    user: &str,
    port: &str,
    rem_address: &str,
    cmd: &str,
    cmd_args: Option<&Vec<String>>,
) -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::START | TacacsAccountingFlags::STOP,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: user.to_owned(),
        port: port.to_owned(),
        rem_address: rem_address.to_owned(),
        args: build_accounting_args(cmd, cmd_args),
    }
}

/// Builds the argument list for an accounting request.
fn build_accounting_args(cmd: &str, cmd_args: Option<&Vec<String>>) -> Vec<String> {
    let base_args = ["service=shell".to_owned(), format!("cmd={cmd}")];

    let extra_args = cmd_args
        .into_iter()
        .flatten()
        .map(|arg| format!("cmd-arg={arg}"));

    base_args.into_iter().chain(extra_args).collect()
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
