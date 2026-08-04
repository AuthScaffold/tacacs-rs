use std::os::raw::c_int;

use tacacsrs_agent_client::{
    AuthorizationArg, AuthorizationAuthenticationContext, AuthorizationKey, AuthorizationOperation,
    AuthorizationResponseStatus, IpcEndpoint, ServiceClient,
};

use crate::config::{format_endpoint, ipc_endpoint};
use crate::logging::debug_log;
use crate::runtime::RUNTIME;
use crate::session::task_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationDecision {
    Allow,
    Deny,
    Unavailable,
}

pub(crate) fn authorize_command(
    flags: c_int,
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
        authentication_context: AuthorizationAuthenticationContext::TacacsAscii,
        args: authorization_args(command, argv),
    };

    if let Err(error) = request.validate() {
        debug_log(
            flags,
            &format!("authorization request validation failed for user {user}: {error}"),
        );
        return AuthorizationDecision::Deny;
    }

    let runtime = match RUNTIME.as_ref() {
        Ok(runtime) => runtime,
        Err(error) => {
            debug_log(flags, &format!("authorization runtime unavailable: {error}"));
            return AuthorizationDecision::Unavailable;
        }
    };

    let endpoint = match ipc_endpoint() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            debug_log(flags, &format!("failed to resolve IPC endpoint: {error}"));
            return AuthorizationDecision::Unavailable;
        }
    };

    debug_log(
        flags,
        &format!(
            "sending authorization request for user {user} on tty {port} from {remote_address} via {}",
            format_endpoint(&endpoint)
        ),
    );

    let response = runtime.block_on(async move {
        let client = connect_client(flags, endpoint).await?;
        client.send_authorization(request).await
    });

    match response {
        Ok(response) => {
            debug_log(flags, &format!("authorization response status: {:?}", response.status));
            match response.status {
                AuthorizationResponseStatus::PassAdd | AuthorizationResponseStatus::PassRepl => {
                    AuthorizationDecision::Allow
                }
                AuthorizationResponseStatus::Fail
                | AuthorizationResponseStatus::Error
                | AuthorizationResponseStatus::Follow => AuthorizationDecision::Deny,
            }
        }
        Err(error) => {
            debug_log(flags, &format!("authorization request failed: {error}"));
            AuthorizationDecision::Unavailable
        }
    }
}

async fn connect_client(flags: c_int, endpoint: IpcEndpoint) -> anyhow::Result<ServiceClient> {
    let client = ServiceClient::connect(endpoint).await?;
    debug_log(flags, "IPC connection to tacacsrs-agentd established");
    Ok(client)
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
