use anyhow::Context;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus, AuthorizationArg,
    AuthorizationOperation, AuthorizationOperationResponse, AuthorizationResponseStatus,
};
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::authorization::request::AuthorizationRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType, TacacsAuthorizationStatus,
};

/// Converts a domain [`AccountingOperation`] into a TACACS+ accounting request
/// message with the standard service-level defaults (WATCHDOG flags, no
/// privilege level, shell service type).
pub(super) fn build_accounting_request(request: &AccountingOperation) -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::START | TacacsAccountingFlags::STOP,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: request.user.clone(),
        port: request.port.clone(),
        rem_address: request.remote_address.clone(),
        args: build_accounting_args(&request.command, &request.command_arguments),
    }
}

/// Builds the TACACS+ argument list for an accounting request.
///
/// The resulting list always starts with `service=shell` and `cmd=<command>`,
/// followed by one `cmd-arg=<arg>` entry for each element of
/// `command_arguments`.
fn build_accounting_args(command: &str, command_arguments: &[String]) -> Vec<String> {
    let base_args = ["service=shell".to_owned(), format!("cmd={command}")];
    let extra_args = command_arguments.iter().map(|arg| format!("cmd-arg={arg}"));
    base_args.into_iter().chain(extra_args).collect()
}

/// Converts a domain [`AuthorizationOperation`] into a TACACS+ authorization
/// request message with service-level authentication context defaults.
pub(super) fn build_authorization_request(
    request: &AuthorizationOperation,
) -> anyhow::Result<AuthorizationRequest> {
    let priv_lvl = u8::try_from(request.privilege_level)
        .context("authorization privilege level exceeds TACACS+ u8 field")?;
    Ok(AuthorizationRequest {
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus,
        priv_lvl,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeAscii,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
        user: request.user.clone(),
        port: request.port.clone(),
        rem_address: request.remote_address.clone(),
        args: request.args.iter().map(format_authorization_arg).collect(),
    })
}

fn format_authorization_arg(arg: &AuthorizationArg) -> String {
    let separator = if arg.mandatory {
        '='
    } else {
        '*'
    };
    format!("{}{separator}{}", arg.name, arg.value)
}

/// Converts a TACACS+ accounting reply into the IPC domain response.
pub(super) fn to_accounting_response(
    address: &str,
    reply: AccountingReply,
) -> AccountingOperationResponse {
    AccountingOperationResponse {
        server: address.to_owned(),
        status: accounting_status(reply.status),
        server_message: reply.server_msg,
        data: reply.data,
    }
}

const fn accounting_status(status: TacacsAccountingStatus) -> AccountingResponseStatus {
    match status {
        TacacsAccountingStatus::TacPlusAcctStatusSuccess => AccountingResponseStatus::Success,
        TacacsAccountingStatus::TacPlusAcctStatusError => AccountingResponseStatus::Error,
        TacacsAccountingStatus::TacPlusAcctStatusFollow => AccountingResponseStatus::Follow,
    }
}

/// Converts a TACACS+ authorization reply into the IPC domain response.
pub(super) fn to_authorization_response(
    address: &str,
    reply: AuthorizationReply,
) -> anyhow::Result<AuthorizationOperationResponse> {
    Ok(AuthorizationOperationResponse {
        server: address.to_owned(),
        status: authorization_status(reply.status),
        server_message: reply.server_msg,
        args: parse_authorization_args(reply.args)?,
        data: reply.data,
    })
}

const fn authorization_status(status: TacacsAuthorizationStatus) -> AuthorizationResponseStatus {
    match status {
        TacacsAuthorizationStatus::TacPlusPassAdd => AuthorizationResponseStatus::PassAdd,
        TacacsAuthorizationStatus::TacPlusPassRepl => AuthorizationResponseStatus::PassRepl,
        TacacsAuthorizationStatus::TacPlusFail => AuthorizationResponseStatus::Fail,
        TacacsAuthorizationStatus::TacPlusError => AuthorizationResponseStatus::Error,
        TacacsAuthorizationStatus::TacPlusFollow => AuthorizationResponseStatus::Follow,
    }
}

fn parse_authorization_args(args: Vec<String>) -> anyhow::Result<Vec<AuthorizationArg>> {
    args.into_iter()
        .map(|arg| AuthorizationArg::parse(&arg))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_accounting_args() {
        let args = build_accounting_args("show", &["users".to_owned(), "brief".to_owned()]);
        assert_eq!(
            args,
            vec![
                "service=shell",
                "cmd=show",
                "cmd-arg=users",
                "cmd-arg=brief"
            ]
        );
    }

    #[test]
    fn test_build_accounting_request_uses_standard_fields_only() {
        let request = build_accounting_request(&AccountingOperation {
            user: "user".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned()],
        });
        assert_eq!(request.user, "user");
        assert_eq!(request.port, "tty0");
        assert_eq!(request.rem_address, "127.0.0.1");
        assert_eq!(request.args, vec!["service=shell", "cmd=show", "cmd-arg=users"]);
    }

    #[test]
    fn test_build_authorization_request_maps_domain_fields() {
        let request = build_authorization_request(
            &AuthorizationOperation::builder("admin", 15)
                .port("pts/1")
                .remote_address("192.0.2.10")
                .service("shell")
                .command("show")
                .command_arg("users")
                .build()
                .unwrap(),
        )
        .unwrap();

        assert_eq!(request.user, "admin");
        assert_eq!(request.port, "pts/1");
        assert_eq!(request.rem_address, "192.0.2.10");
        assert_eq!(request.priv_lvl, 15);
        assert_eq!(request.args, vec!["service=shell", "cmd=show", "cmd-arg=users"]);
    }
}
