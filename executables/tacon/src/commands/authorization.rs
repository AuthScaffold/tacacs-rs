//! Explicit shell session and command authorization.

use tacacsrs_protocol::operations::{
    AuthorizationAuthenticationContext, AuthorizationOperation, AuthorizationOperationResponse,
};

use crate::cli::{AuthorizationAuthContext, AuthorizationMode, RequestArgs};
use crate::connection::Connection;

/// Sends a prepared authorization operation over a direct TACACS+ connection.
///
/// # Errors
///
/// Returns an error if the exchange fails or the reply is malformed.
pub(crate) async fn send_direct(
    connection: &Connection,
    operation: &AuthorizationOperation,
) -> anyhow::Result<AuthorizationOperationResponse> {
    let reply = connection.execute(&operation.exchange()?).await?;
    AuthorizationOperationResponse::from_reply(connection.server_name(), reply)
}

/// Builds an [`AuthorizationOperation`] from CLI arguments.
///
/// # Errors
///
/// Returns an error if the assembled operation is invalid.
pub(crate) fn authorization_operation(
    args: &RequestArgs,
    privilege_level: u8,
    context: AuthorizationAuthContext,
    mode: &AuthorizationMode,
) -> anyhow::Result<AuthorizationOperation> {
    let mut builder = AuthorizationOperation::builder(
        args.user.clone(),
        u32::from(privilege_level),
        authentication_context(context),
    )
    .port(args.port.clone())
    .remote_address(args.rem_addr.clone())
    .service("shell");
    match mode {
        AuthorizationMode::Session => builder = builder.command(""),
        AuthorizationMode::Command { command, arguments } => {
            builder = builder
                .command(command.clone())
                .command_args(arguments.clone());
        }
    }
    builder.build()
}

const fn authentication_context(
    context: AuthorizationAuthContext,
) -> AuthorizationAuthenticationContext {
    match context {
        AuthorizationAuthContext::Ascii => AuthorizationAuthenticationContext::TacacsAscii,
        AuthorizationAuthContext::Pap => AuthorizationAuthenticationContext::TacacsPap,
        AuthorizationAuthContext::Unauthenticated => {
            AuthorizationAuthenticationContext::Unauthenticated
        }
    }
}
