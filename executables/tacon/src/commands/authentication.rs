//! Fixed PAP authentication command support.

use std::io::{IsTerminal, Read};

use anyhow::Context;
#[cfg(target_os = "linux")]
use tacacsrs_agent_client::{ServiceClient};
use tacacsrs_protocol::operations::PapAuthenticationOperation;
#[cfg(target_os = "linux")]
use tacacsrs_protocol::operations::PapAuthenticationOperationResponse;
use tacacsrs_protocol::authentication::reply::AuthenticationReply;
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
        .execute(pap_operation(args, privilege_level, password)?.exchange()?)
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
        .authenticate_pap(pap_operation(args, privilege_level, password)?)
        .await
}

fn pap_operation(
    args: &RequestArgs,
    privilege_level: u8,
    password: SecretBytes,
) -> anyhow::Result<PapAuthenticationOperation> {
    let operation = PapAuthenticationOperation {
        user: args.user.clone(),
        password,
        port: args.port.clone(),
        remote_address: args.rem_addr.clone(),
        privilege_level: tacacsrs_protocol::privilege::PrivilegeLevel::try_from(privilege_level)?,
    };
    operation.validate()?;
    Ok(operation)
}
