//! Domain request builders shared by agent tests.

use tacacsrs_agent_client::{AccountingOperation, AuthorizationOperation};

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
    AuthorizationOperation::builder("admin", 15)
        .port("tty0")
        .remote_address("127.0.0.1")
        .service("shell")
        .command("show")
        .command_arg("users")
        .build()
        .expect("test authorization request is valid")
}
