//! Domain request builders for agent tests.

#[cfg(unix)]
use tacacsrs_agent_client::AccountingOperation;
use tacacsrs_agent_client::{AuthorizationAuthenticationContext, AuthorizationOperation};

#[cfg(unix)]
pub(crate) fn build_request() -> AccountingOperation {
    AccountingOperation {
        user: "admin".to_owned(),
        port: "tty0".to_owned(),
        remote_address: "127.0.0.1".to_owned(),
        command: "show".to_owned(),
        command_arguments: vec!["users".to_owned()],
    }
}

pub(crate) fn build_authorization_request() -> AuthorizationOperation {
    AuthorizationOperation::builder("admin", 15, AuthorizationAuthenticationContext::TacacsAscii)
        .port("tty0")
        .remote_address("127.0.0.1")
        .service("shell")
        .command("show")
        .command_arg("users")
        .build()
        .expect("the test authorization request must be valid")
}
