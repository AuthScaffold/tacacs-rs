//! Portable authorization decision mapping for `session-wrapper`.

use std::fmt::Write as _;

use tacacsrs_agent_client::{
    AuthorizationArg, AuthorizationOperationResponse, AuthorizationResponseStatus,
};

use crate::cli::FailPolicy;
use crate::deny::non_empty;

/// Outcome of an authorization decision for one exec notification.
#[derive(Debug)]
pub(crate) enum AuthDecision {
    /// Allow the exec to proceed.
    Allow,
    /// Deny the exec; the platform backend maps this to its native denial.
    Deny(DenyDecision),
}

/// Rich context for deny decisions.
#[derive(Debug)]
pub(crate) struct DenyDecision {
    pub(crate) source: DenySource,
    pub(crate) reason: String,
    pub(crate) server: Option<String>,
    pub(crate) server_message: Option<String>,
    pub(crate) fail_policy: Option<FailPolicy>,
}

/// Source of a deny decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DenySource {
    AuthorizationDenied,
    ServiceUnavailableFailClosed,
}

/// Maps an authorization response into the local execution decision.
///
/// Seccomp user notification can either continue the original frozen `execve`
/// or deny it; it cannot inject additional argv values or replace the submitted
/// argv. RFC 8907 lets clients ignore optional response args, but mandatory
/// response args must be applied or authorization fails.
pub(crate) fn map_authorization_response(
    response: &AuthorizationOperationResponse,
    exec_path: &str,
) -> AuthDecision {
    let server = non_empty(Some(response.server.as_str())).map(str::to_owned);
    let server_message = non_empty(Some(response.server_message.as_str())).map(str::to_owned);

    match response.status {
        AuthorizationResponseStatus::PassAdd => map_pass_with_args(
            "PASS_ADD",
            "response",
            response.args.as_slice(),
            exec_path,
            server,
            server_message,
        ),
        AuthorizationResponseStatus::PassRepl => map_pass_with_args(
            "PASS_REPL",
            "replacement",
            response.args.as_slice(),
            exec_path,
            server,
            server_message,
        ),
        AuthorizationResponseStatus::Fail
        | AuthorizationResponseStatus::Error
        | AuthorizationResponseStatus::Follow => {
            let mut reason =
                format!("TACACS+ agent denied {exec_path:?}: status={:?}", response.status);
            if let Some(message) = server_message.as_deref() {
                let _ = write!(reason, ", server_message={message:?}");
            }

            AuthDecision::Deny(DenyDecision {
                source: DenySource::AuthorizationDenied,
                reason,
                server,
                server_message,
                fail_policy: None,
            })
        }
    }
}

/// Maps a fail policy to an [`AuthDecision`] for when IPC is unavailable.
pub(crate) fn fail_policy_decision(policy: FailPolicy, exec_path: &str) -> AuthDecision {
    match policy {
        FailPolicy::Open => {
            log::warn!("IPC unavailable, fail-open: allowing {exec_path:?}");
            AuthDecision::Allow
        }
        FailPolicy::Closed => {
            let reason = format!("IPC unavailable, fail-closed: denying {exec_path:?}");
            log::warn!("{reason}");
            AuthDecision::Deny(DenyDecision {
                source: DenySource::ServiceUnavailableFailClosed,
                reason,
                server: None,
                server_message: None,
                fail_policy: Some(FailPolicy::Closed),
            })
        }
    }
}

fn map_pass_with_args(
    status_name: &str,
    arg_kind: &str,
    args: &[AuthorizationArg],
    exec_path: &str,
    server: Option<String>,
    server_message: Option<String>,
) -> AuthDecision {
    if args.is_empty() {
        return AuthDecision::Allow;
    }

    let arg_names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    let mandatory_names: Vec<&str> = args
        .iter()
        .filter(|a| a.mandatory)
        .map(|a| a.name.as_str())
        .collect();

    if mandatory_names.is_empty() {
        log::warn!(
            "IPC authorization {status_name} for {exec_path:?} returned optional {arg_kind} \
             args {arg_names:?} that cannot be applied in seccomp notify mode; ignoring them"
        );
        AuthDecision::Allow
    } else {
        log::warn!(
            "IPC authorization {status_name} for {exec_path:?} returned mandatory {arg_kind} \
             args {mandatory_names:?} (all args: {arg_names:?}) that cannot be applied in seccomp \
             notify mode; treating as failed per RFC 8907 §6.2"
        );
        AuthDecision::Deny(DenyDecision {
            source: DenySource::AuthorizationDenied,
            reason: format!(
                "TACACS+ agent returned {status_name} for {exec_path:?} with mandatory {arg_kind} \
                 arg(s) that cannot be applied: {mandatory_names:?}"
            ),
            server,
            server_message,
            fail_policy: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_agent_client::{
        AuthorizationArg, AuthorizationOperationResponse, AuthorizationResponseStatus,
    };

    use super::{AuthDecision, DenySource, map_authorization_response};

    fn authorization_response(
        status: AuthorizationResponseStatus,
        args: Vec<AuthorizationArg>,
    ) -> AuthorizationOperationResponse {
        AuthorizationOperationResponse {
            server: "test-server".to_owned(),
            status,
            server_message: String::new(),
            args,
            data: String::new(),
        }
    }

    #[test]
    fn pass_add_with_only_optional_response_args_is_allowed() {
        let response = authorization_response(
            AuthorizationResponseStatus::PassAdd,
            vec![AuthorizationArg::optional("priv-lvl", "15")],
        );

        let decision = map_authorization_response(&response, "/bin/echo");

        assert!(matches!(decision, AuthDecision::Allow));
    }

    #[test]
    fn pass_repl_with_only_optional_replacement_args_is_allowed() {
        let response = authorization_response(
            AuthorizationResponseStatus::PassRepl,
            vec![AuthorizationArg::optional("cmd-arg", "ignored")],
        );

        let decision = map_authorization_response(&response, "/bin/echo");

        assert!(matches!(decision, AuthDecision::Allow));
    }

    #[test]
    fn pass_add_with_mandatory_response_arg_is_denied() {
        let response = authorization_response(
            AuthorizationResponseStatus::PassAdd,
            vec![AuthorizationArg::mandatory("priv-lvl", "15")],
        );

        let decision = map_authorization_response(&response, "/bin/echo");

        match decision {
            AuthDecision::Deny(deny) => assert!(deny.reason.contains("priv-lvl")),
            AuthDecision::Allow => panic!("mandatory PASS_ADD response arg was allowed"),
        }
    }

    #[test]
    fn pass_repl_with_mandatory_replacement_arg_is_denied() {
        let response = authorization_response(
            AuthorizationResponseStatus::PassRepl,
            vec![AuthorizationArg::mandatory("cmd", "/bin/date")],
        );

        let decision = map_authorization_response(&response, "/bin/echo");

        match decision {
            AuthDecision::Deny(deny) => assert!(deny.reason.contains("cmd")),
            AuthDecision::Allow => panic!("mandatory PASS_REPL replacement arg was allowed"),
        }
    }

    #[test]
    fn authorization_fail_status_is_denied_without_fail_policy() {
        let mut response = authorization_response(AuthorizationResponseStatus::Fail, Vec::new());
        response.server_message = "no authorization rule matched request".to_owned();

        let decision = map_authorization_response(&response, "/usr/bin/htop");

        match decision {
            AuthDecision::Deny(deny) => {
                assert_eq!(deny.source, DenySource::AuthorizationDenied);
                assert_eq!(deny.fail_policy, None);
                assert_eq!(
                    deny.server_message.as_deref(),
                    Some("no authorization rule matched request")
                );
            }
            AuthDecision::Allow => panic!("authorization Fail status was allowed"),
        }
    }

    #[test]
    fn authorization_error_status_is_denied_without_fail_policy() {
        let mut response = authorization_response(AuthorizationResponseStatus::Error, Vec::new());
        response.server_message = "authorization policy evaluation failed".to_owned();

        let decision = map_authorization_response(&response, "/usr/bin/htop");

        match decision {
            AuthDecision::Deny(deny) => {
                assert_eq!(deny.source, DenySource::AuthorizationDenied);
                assert_eq!(deny.fail_policy, None);
                assert_eq!(
                    deny.server_message.as_deref(),
                    Some("authorization policy evaluation failed")
                );
            }
            AuthDecision::Allow => panic!("authorization Error status was allowed"),
        }
    }
}
