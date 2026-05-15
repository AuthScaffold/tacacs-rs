use tacacsrs_agent_client::{
    AuthorizationArg, AuthorizationKey, AuthorizationOperation, AuthorizationResponseStatus,
    ServiceClient,
};

use crate::config::ipc_endpoint;
use crate::runtime::RUNTIME;
use crate::session::task_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationDecision {
    Allow,
    Deny,
    Unavailable,
}

pub(crate) fn authorize_command(
    user: &str,
    port: &str,
    remote_address: &str,
    command: &str,
    argv: &[String],
) -> AuthorizationDecision {
    let request = AuthorizationOperation {
        user: user.to_owned(),
        port: port.to_owned(),
        remote_address: remote_address.to_owned(),
        privilege_level: 15,
        args: authorization_args(command, argv),
    };

    if request.validate().is_err() {
        return AuthorizationDecision::Deny;
    }

    let runtime = match RUNTIME.as_ref() {
        Ok(runtime) => runtime,
        Err(_) => return AuthorizationDecision::Unavailable,
    };

    let response = runtime.block_on(async move {
        let client = ServiceClient::connect(ipc_endpoint()?).await?;
        client.send_authorization(request).await
    });

    match response {
        Ok(response) => match response.status {
            AuthorizationResponseStatus::PassAdd | AuthorizationResponseStatus::PassRepl => {
                AuthorizationDecision::Allow
            }
            AuthorizationResponseStatus::Fail
            | AuthorizationResponseStatus::Error
            | AuthorizationResponseStatus::Follow => AuthorizationDecision::Deny,
        },
        Err(_) => AuthorizationDecision::Unavailable,
    }
}

fn authorization_args(command: &str, argv: &[String]) -> Vec<AuthorizationArg> {
    let task_id = task_id().to_string();
    let mut args = vec![
        AuthorizationArg::mandatory("task_id", task_id),
        AuthorizationArg::mandatory_key(AuthorizationKey::Protocol, "ssh"),
        AuthorizationArg::mandatory_key(AuthorizationKey::Service, "shell"),
        AuthorizationArg::mandatory_key(AuthorizationKey::Cmd, command),
    ];

    args.extend(
        argv.iter().skip(1).map(|arg| {
            AuthorizationArg::mandatory_key(AuthorizationKey::CmdArg, truncate_arg(arg))
        }),
    );
    args
}

fn truncate_arg(value: &str) -> String {
    value.chars().take(247).collect()
}
