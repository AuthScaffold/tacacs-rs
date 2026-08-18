//! Explicit shell session and command authorization.

#[cfg(target_os = "linux")]
use tacacsrs_agent_client::{
    AuthorizationAuthenticationContext, AuthorizationOperation, AuthorizationOperationResponse,
    ServiceClient,
};
use tacacsrs_flows::authorization::{AuthenticationContext, AuthorizationExchange};
use tacacsrs_messages::authorization::reply::AuthorizationReply;

use crate::cli::{AuthorizationAuthContext, AuthorizationMode, RequestArgs};
use crate::connection::Connection;

pub async fn authorize_direct(
    connection: &Connection,
    args: &RequestArgs,
    privilege_level: u8,
    context: AuthorizationAuthContext,
    mode: &AuthorizationMode,
) -> anyhow::Result<AuthorizationReply> {
    let context = flow_context(context);
    let exchange = match mode {
        AuthorizationMode::Session => AuthorizationExchange::shell_session(
            context,
            args.user.clone(),
            args.port.clone(),
            args.rem_addr.clone(),
            privilege_level,
        ),
        AuthorizationMode::Command { command, arguments } => AuthorizationExchange::shell_command(
            context,
            args.user.clone(),
            args.port.clone(),
            args.rem_addr.clone(),
            privilege_level,
            command.clone(),
            arguments.clone(),
        ),
    };
    connection.execute(exchange).await
}

#[cfg(target_os = "linux")]
pub async fn authorize_service(
    client: &ServiceClient,
    args: &RequestArgs,
    privilege_level: u8,
    context: AuthorizationAuthContext,
    mode: &AuthorizationMode,
) -> anyhow::Result<AuthorizationOperationResponse> {
    let mut builder = AuthorizationOperation::builder(
        args.user.clone(),
        u32::from(privilege_level),
        ipc_context(context),
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
    client.send_authorization(builder.build()?).await
}

const fn flow_context(context: AuthorizationAuthContext) -> AuthenticationContext {
    match context {
        AuthorizationAuthContext::Ascii => AuthenticationContext::TacacsAscii,
        AuthorizationAuthContext::Pap => AuthenticationContext::TacacsPap,
        AuthorizationAuthContext::Unauthenticated => AuthenticationContext::Unauthenticated,
    }
}

#[cfg(target_os = "linux")]
const fn ipc_context(context: AuthorizationAuthContext) -> AuthorizationAuthenticationContext {
    match context {
        AuthorizationAuthContext::Ascii => AuthorizationAuthenticationContext::TacacsAscii,
        AuthorizationAuthContext::Pap => AuthorizationAuthenticationContext::TacacsPap,
        AuthorizationAuthContext::Unauthenticated => {
            AuthorizationAuthenticationContext::Unauthenticated
        }
    }
}
