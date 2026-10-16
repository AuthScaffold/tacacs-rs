//! Explicit shell session and command authorization.

#[cfg(target_os = "linux")]
use tacacsrs_agent_client::{ServiceClient};
use tacacsrs_protocol::operations::{AuthorizationAuthenticationContext, AuthorizationOperation};
#[cfg(target_os = "linux")]
use tacacsrs_protocol::operations::AuthorizationOperationResponse;
use tacacsrs_protocol::authorization::reply::AuthorizationReply;

use crate::cli::{AuthorizationAuthContext, AuthorizationMode, RequestArgs};
use crate::connection::Connection;

pub async fn authorize_direct(
    connection: &Connection,
    args: &RequestArgs,
    privilege_level: u8,
    context: AuthorizationAuthContext,
    mode: &AuthorizationMode,
) -> anyhow::Result<AuthorizationReply> {
    let operation = authorization_operation(args, privilege_level, context, mode)?;
    connection.execute(operation.exchange()?).await
}

#[cfg(target_os = "linux")]
pub async fn authorize_service(
    client: &ServiceClient,
    args: &RequestArgs,
    privilege_level: u8,
    context: AuthorizationAuthContext,
    mode: &AuthorizationMode,
) -> anyhow::Result<AuthorizationOperationResponse> {
    client
        .send_authorization(authorization_operation(args, privilege_level, context, mode)?)
        .await
}

fn authorization_operation(
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
