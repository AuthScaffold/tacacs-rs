use tacacsrs_protocol::operations::{
    AuthorizationArg, AuthorizationOperationResponse, AuthorizationResponseStatus,
};

pub(super) fn unchanged_execution_cases() -> Vec<(String, AuthorizationOperationResponse, bool)> {
    let mut cases = Vec::new();
    for status in [
        AuthorizationResponseStatus::PassAdd,
        AuthorizationResponseStatus::PassRepl,
        AuthorizationResponseStatus::Fail,
        AuthorizationResponseStatus::Error,
        AuthorizationResponseStatus::Follow,
    ] {
        for (name, args, supported) in [
            ("empty", vec![], true),
            ("optional", vec![AuthorizationArg::optional("protocol", "ssh")], true),
            ("mandatory-command", vec![AuthorizationArg::mandatory("cmd", "/bin/date")], false),
            ("mandatory-privilege", vec![AuthorizationArg::mandatory("priv-lvl", "15")], false),
            ("malformed-name", vec![AuthorizationArg::optional("", "invalid")], false),
        ] {
            let allowed = supported
                && matches!(
                    status,
                    AuthorizationResponseStatus::PassAdd | AuthorizationResponseStatus::PassRepl
                );
            cases.push((
                format!("{status:?}/{name}"),
                AuthorizationOperationResponse {
                    server: "primary".to_owned(),
                    status,
                    args,
                    server_message: "policy result".to_owned(),
                    data: String::new(),
                },
                allowed,
            ));
        }
    }
    cases
}
