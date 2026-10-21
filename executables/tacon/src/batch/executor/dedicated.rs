//! Dedicated direct-backend establishment for batch execution.

use anyhow::Context;

use tacacsrs_config::TacacsPlusServer;
use tacacsrs_config::prepare::PrepareOptions;

use crate::backend::Backend;
use crate::connection::establish_dedicated_connection;

use super::super::types::{BatchRequest, RequestResult};

/// Establishes a dedicated direct backend with TACACS+ single-connection disabled.
///
/// Each request opens its own direct TCP or TLS connection to the server,
/// without background tasks or session multiplexing.
///
/// # Errors
///
/// Returns an error if the dedicated connection cannot be established.
pub(super) async fn establish_dedicated_backend(
    server: &TacacsPlusServer,
    options: PrepareOptions,
) -> anyhow::Result<Backend> {
    let connection = establish_dedicated_connection(server, options)
        .await
        .context("Failed to establish dedicated TACACS+ connection")?;
    Ok(Backend::Direct(connection))
}

/// Reports a dedicated connection failure once for every request in the batch.
///
/// Non-load-test dedicated runs do not abort when the connection fails. Instead
/// the summary lists each request as failed with the same message.
pub(super) fn connection_failure_results(
    requests: &[BatchRequest],
    error: &anyhow::Error,
) -> Vec<RequestResult> {
    let message = format!("Connection failed: {error:#}");
    requests
        .iter()
        .enumerate()
        .map(|(index, request)| RequestResult {
            index,
            request_type: request.type_name(),
            result: Err(message.clone()),
        })
        .collect()
}
