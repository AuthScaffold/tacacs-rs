//! Multiplexed direct-backend establishment for batch execution.

use anyhow::Context;

use tacacsrs_config::TacacsPlusServer;
use tacacsrs_config::prepare::PrepareOptions;

use crate::backend::Backend;
use crate::connection::establish_connection;

/// Establishes an adaptive single-connection direct backend.
///
/// The first request can negotiate single-connection support. Later requests
/// reuse the upgraded shared transport.
///
/// # Errors
///
/// Returns an error if the connection cannot be established.
pub(super) async fn establish_multiplexed_backend(
    server: &TacacsPlusServer,
    options: PrepareOptions,
) -> anyhow::Result<Backend> {
    let connection = establish_connection(server, options)
        .await
        .context("Failed to establish multiplexed TACACS+ connection")?;
    Ok(Backend::Direct(connection))
}
