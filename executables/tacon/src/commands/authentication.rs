//! Fixed PAP authentication command support.

use std::io::{IsTerminal, Read};

use anyhow::Context;
use tacacsrs_protocol::operations::{PapAuthenticationOperation, PapAuthenticationOperationResponse};
use tacacsrs_secrets::SecretBytes;

use crate::cli::RequestArgs;
use crate::connection::Connection;

pub(crate) fn read_password(from_stdin: bool) -> anyhow::Result<SecretBytes> {
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

/// Sends a prepared PAP authentication operation over a direct TACACS+ connection.
///
/// # Errors
///
/// Returns an error if the exchange fails or the reply is nonterminal.
pub(crate) async fn send_direct(
    connection: &Connection,
    operation: &PapAuthenticationOperation,
) -> anyhow::Result<PapAuthenticationOperationResponse> {
    let reply = connection.execute(operation.exchange()?).await?;
    PapAuthenticationOperationResponse::from_reply(connection.server_name(), reply)
}

/// Builds a validated [`PapAuthenticationOperation`] from CLI arguments.
///
/// # Errors
///
/// Returns an error if the privilege level or the assembled operation is invalid.
pub(crate) fn pap_operation(
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
