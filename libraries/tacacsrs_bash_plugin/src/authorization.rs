use std::os::raw::c_int;

use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
use tacacsrs_protocol::operations::{
    AuthorizationArg, AuthorizationAuthenticationContext, AuthorizationKey, AuthorizationOperation,
    AuthorizationResponseStatus,
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
    let request = match authorization_request(user, port, remote_address, command, argv) {
        Ok(request) => request,
        Err(error) => {
            debug_log(flags, &format!("authorization request is invalid for user {user}: {error}"));
            return AuthorizationDecision::Deny;
        }
    };

    let runtime = match RUNTIME.as_ref() {
        Ok(runtime) => runtime,
        Err(error) => {
            debug_log(flags, &format!("authorization runtime is unavailable: {error}"));
            return AuthorizationDecision::Unavailable;
        }
    };

    let endpoint = match ipc_endpoint() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            debug_log(flags, &format!("failed to resolve the IPC endpoint: {error}"));
            return AuthorizationDecision::Unavailable;
        }
    };

    debug_log(
        flags,
        &format!(
            "sending an authorization request for user {user} on tty {port} from {remote_address} through {}",
            format_endpoint(&endpoint)
        ),
    );

    let response = runtime.block_on(async move {
        let client = connect_client(flags, endpoint).await?;
        client
            .send_authorization(request)
            .await
            .map_err(anyhow::Error::from)
    });

    match response {
        Ok(response) => {
            debug_log(flags, &format!("authorization response status is {:?}", response.status));
            response_decision(response.status, &response.args)
        }
        Err(error) => {
            debug_log(flags, &format!("authorization request returned an error: {error}"));
            AuthorizationDecision::Unavailable
        }
    }
}

fn response_decision(
    status: AuthorizationResponseStatus,
    args: &[AuthorizationArg],
) -> AuthorizationDecision {
    match status.unchanged_execution(args) {
        tacacsrs_protocol::operations::UnchangedExecutionDecision::Allow => {
            AuthorizationDecision::Allow
        }
        _ => AuthorizationDecision::Deny,
    }
}

async fn connect_client(flags: c_int, endpoint: IpcEndpoint) -> anyhow::Result<ServiceClient> {
    let client = ServiceClient::connect(endpoint).await?;
    debug_log(flags, "connected to tacacsrs-agentd through IPC");
    Ok(client)
}

fn authorization_request(
    user: &str,
    port: &str,
    remote_address: &str,
    command: &str,
    argv: &[String],
) -> anyhow::Result<AuthorizationOperation> {
    let request = AuthorizationOperation::builder(
        user,
        u32::from(tacacsrs_protocol::privilege::PrivilegeLevel::MAX),
        AuthorizationAuthenticationContext::TacacsAscii,
    )
    .port(port)
    .remote_address(remote_address)
    .arg(AuthorizationArg::mandatory("task_id", task_id().to_string()))
    .key_value(AuthorizationKey::Protocol, true, "ssh")
    .service("shell")
    .command(command)
    .command_args(argv.iter().skip(1).map(|argument| truncate_arg(argument)))
    .build()?;
    request.exchange()?;
    Ok(request)
}

fn truncate_arg(value: &str) -> String {
    value.chars().take(247).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    mod conformance {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tacacsrs_protocol/test_support/authorization.rs"
        ));
    }

    #[test]
    fn shared_unchanged_execution_conformance() {
        for (name, response, allowed) in conformance::unchanged_execution_cases() {
            let expected = if allowed {
                AuthorizationDecision::Allow
            } else {
                AuthorizationDecision::Deny
            };
            assert_eq!(response_decision(response.status, &response.args), expected, "{name}");
        }
    }

    #[test]
    fn builder_preserves_exact_command_metadata_and_character_truncation() {
        let argv = vec!["ignored-argv-zero".into(), "users".into(), "x".repeat(248)];
        let request = authorization_request("admin", "tty7", "192.0.2.7", "show", &argv).unwrap();
        assert_eq!(request.user, "admin");
        assert_eq!(request.port, "tty7");
        assert_eq!(request.remote_address, "192.0.2.7");
        assert_eq!(request.privilege_level, tacacsrs_protocol::privilege::PrivilegeLevel::MAX);
        assert_eq!(request.authentication_context, AuthorizationAuthenticationContext::TacacsAscii);
        assert_eq!(
            request
                .args
                .iter()
                .map(AuthorizationArg::to_wire)
                .collect::<Vec<_>>(),
            vec![
                format!("task_id={}", task_id()),
                "protocol=ssh".into(),
                "service=shell".into(),
                "cmd=show".into(),
                "cmd-arg=users".into(),
                format!("cmd-arg={}", "x".repeat(247)),
            ]
        );
        assert_eq!(truncate_arg(&"\u{e9}".repeat(248)).chars().count(), 247);
    }

    #[test]
    fn invalid_byte_length_denies_before_ipc_or_fallback() {
        let argv = vec!["show".into(), "\u{e9}".repeat(247)];
        assert!(authorization_request("admin", "tty0", "", "show", &argv).is_err());
        assert_eq!(
            authorize_command(0, "admin", "tty0", "", "show", &argv),
            AuthorizationDecision::Deny
        );
        assert_eq!(
            authorize_command(0, &"x".repeat(256), "tty0", "", "show", &[]),
            AuthorizationDecision::Deny
        );
    }
}
