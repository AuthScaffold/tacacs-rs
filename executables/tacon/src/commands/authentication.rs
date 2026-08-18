//! Fixed PAP authentication command support.

use std::io::{IsTerminal, Read};

use anyhow::Context;
#[cfg(target_os = "linux")]
use tacacsrs_agent_client::{
    PapAuthenticationOperation, PapAuthenticationOperationResponse, ServiceClient,
};
use tacacsrs_flows::authentication::PapAuthenticationExchange;
use tacacsrs_messages::authentication::reply::AuthenticationReply;
use tacacsrs_secrets::SecretBytes;

use crate::cli::RequestArgs;
use crate::connection::Connection;

pub fn read_password(from_stdin: bool) -> anyhow::Result<SecretBytes> {
    let bytes = if from_stdin {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("Failed to read PAP password from standard input")?;
        while matches!(bytes.last(), Some(b'\r' | b'\n')) {
            bytes.pop();
        }
        bytes
    } else {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!("Standard input is not a terminal. Run with --password-stdin instead.")
        }
        rpassword::prompt_password("PAP password: ")
            .context("Failed to read PAP password")?
            .into_bytes()
    };
    Ok(SecretBytes::new(bytes))
}

pub async fn authenticate_direct(
    connection: &Connection,
    args: &RequestArgs,
    privilege_level: u8,
    password: SecretBytes,
) -> anyhow::Result<AuthenticationReply> {
    connection
        .execute(PapAuthenticationExchange::new(
            args.user.clone(),
            password,
            args.port.clone(),
            args.rem_addr.clone(),
            privilege_level,
        ))
        .await
}

#[cfg(target_os = "linux")]
pub async fn authenticate_service(
    client: &ServiceClient,
    args: &RequestArgs,
    privilege_level: u8,
    password: SecretBytes,
) -> anyhow::Result<PapAuthenticationOperationResponse> {
    client
        .authenticate_pap(PapAuthenticationOperation {
            user: args.user.clone(),
            password,
            port: args.port.clone(),
            remote_address: args.rem_addr.clone(),
            privilege_level: u32::from(privilege_level),
        })
        .await
}
