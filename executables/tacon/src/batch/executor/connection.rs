use anyhow::Context;
use futures::future::join_all;

use tacacsrs_networking::session::Session;
use tacacsrs_networking::SingleConnectionState;

use crate::cli::Cli;
use crate::connection::{establish_connection, Connection};

use super::common::{execute_single_request, load_test_iterations, run_load_test};
use super::dedicated::{execute_requests_dedicated, probe_request_dedicated, run_dedicated_load_test};
use super::super::progress::print_load_test_summary;
use super::super::types::{BatchFile, BatchRequest, LoadTestConfig, LoadTestResult, RequestResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostProbeExecutionMode {
    Multiplexed,
    Dedicated,
}

const fn execution_mode_from_probe(single_connect_supported: bool) -> PostProbeExecutionMode {
    if single_connect_supported {
        PostProbeExecutionMode::Multiplexed
    } else {
        PostProbeExecutionMode::Dedicated
    }
}

/// Executes requests sequentially, one at a time
///
/// If the server doesn't support single connection mode, a new connection
/// is established for each subsequent request.
pub(super) async fn execute_sequential(
    cli: &Cli,
    mut connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    let mut results = Vec::with_capacity(requests.len());

    for (index, request) in requests.iter().enumerate() {
        log::info!("Executing request {}/{}", index + 1, requests.len());

        if index > 0 {
            connection = maybe_reconnect(cli, connection, index).await?;
        }

        let custom_session_id = request.session_id();
        let session = connection
            .create_session_optional_id(custom_session_id)
            .await
            .context("Failed to create session for batch request")?;

        if let Some(session_id) = custom_session_id {
            log::info!("Using custom session ID: {session_id}");
        }

        let result = execute_single_request(&session, request).await;
        results.push(RequestResult {
            index,
            request_type: request.type_name(),
            result,
        });
    }

    Ok(results)
}

/// Checks if a new connection is needed and establishes one if necessary
async fn maybe_reconnect(
    cli: &Cli,
    connection: Connection,
    request_index: usize,
) -> anyhow::Result<Connection> {
    match connection.single_connection_state().await {
        SingleConnectionState::NotSupported => {
            log::info!(
                "Server does not support single connection mode. Establishing new connection for request {}",
                request_index + 1
            );
            establish_connection(cli)
                .await
                .context("Failed to establish new connection for batch request")
        }
        SingleConnectionState::Supported => {
            log::debug!(
                "Reusing connection for request {} (single connection mode supported)",
                request_index + 1
            );
            Ok(connection)
        }
        SingleConnectionState::Initial | SingleConnectionState::Negotiating => {
            log::warn!(
                "Unexpected connection state after first request: {:?}",
                connection.single_connection_state().await
            );
            Ok(connection)
        }
    }
}

/// Executes all requests in parallel
///
/// First sends a single request to determine if the server supports single connection mode.
/// If supported, remaining requests are executed in parallel on the same connection.
/// If not supported, remaining requests are each executed on separate connections.
pub(super) async fn execute_parallel(
    cli: &Cli,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    if requests.is_empty() {
        return Ok(vec![]);
    }

    log::info!("Executing first request via dedicated connection to determine single connection mode support");
    let first_probe = probe_request_dedicated(cli, &requests[0], 0).await;
    let mut results = vec![first_probe.request_result];

    if requests.len() == 1 {
        return Ok(results);
    }

    let remaining_requests = &requests[1..];

    if execution_mode_from_probe(first_probe.single_connect_supported)
        == PostProbeExecutionMode::Multiplexed
    {
        let connection = establish_connection(cli)
            .await
            .context("Failed to establish multiplexed connection after dedicated probe")?;
        results.extend(execute_parallel_single_connection(connection, remaining_requests).await?);
    } else {
        log::info!(
            "Server did not confirm single connection mode via dedicated probe. Executing {} remaining requests with dedicated connections",
            remaining_requests.len()
        );
        results.extend(execute_requests_dedicated(cli, remaining_requests, 1, true).await);
    }

    results.sort_by_key(|result| result.index);
    Ok(results)
}

/// Executes requests in parallel using a single shared connection
async fn execute_parallel_single_connection(
    connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    log::info!(
        "Server supports single connection mode. Executing {} requests in parallel on same connection",
        requests.len()
    );

    let mut session_futures = Vec::with_capacity(requests.len());
    for request in requests {
        session_futures.push(connection.create_session_optional_id(request.session_id()));
    }

    let sessions: Vec<Session> = join_all(session_futures)
        .await
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result.with_context(|| format!("Failed to create session for request {}", index + 2))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let futures: Vec<_> = requests
        .iter()
        .zip(sessions.iter())
        .enumerate()
        .map(|(index, (request, session))| {
            let index = index + 1;
            async move {
                log::info!("Starting parallel request {}", index + 1);
                let result = execute_single_request(session, request).await;
                RequestResult {
                    index,
                    request_type: request.type_name(),
                    result,
                }
            }
        })
        .collect();

    Ok(join_all(futures).await)
}

/// Executes a load test by repeating all requests with controlled concurrency
///
/// This function runs all requests multiple times (based on `config.repetitions`)
/// with a maximum of `config.max_parallel` concurrent requests. The test stops
/// immediately on the first failure.
pub(super) async fn execute_load_test(
    cli: &Cli,
    requests: &[BatchRequest],
    config: &LoadTestConfig,
) -> anyhow::Result<LoadTestResult> {
    let total_requests = requests.len() * config.repetitions;

    println!("Starting load test with {total_requests} total requests...\n");

    let cli = cli.clone();
    Ok(run_load_test(
        total_requests,
        load_test_iterations(requests, config.repetitions),
        config.max_parallel,
        move |rep, idx, request| {
            let cli = cli.clone();
            async move { execute_load_test_single(&cli, request, rep, idx).await }
        },
    )
    .await)
}

/// Executes a single load test iteration
async fn execute_load_test_single(
    cli: &Cli,
    request: &BatchRequest,
    rep: usize,
    idx: usize,
) -> Result<(), String> {
    let connection = establish_connection(cli).await.map_err(|error| {
        format!("Connection failed at rep {}, request {}: {}", rep + 1, idx + 1, error)
    })?;

    let session = connection
        .create_session_optional_id(request.session_id())
        .await
        .map_err(|error| {
            format!("Session creation failed at rep {}, request {}: {}", rep + 1, idx + 1, error)
        })?;

    execute_single_request(&session, request)
        .await
        .map(|_| ())
        .map_err(|error| {
            format!(
                "Request failed at rep {}, request {} ({}): {}",
                rep + 1,
                idx + 1,
                request.type_name(),
                error
            )
        })
}

/// Probes the server to check for single-connection support
async fn probe_server_capability(cli: &Cli, requests: &[BatchRequest]) -> bool {
    log::info!("Probing server for single-connection support...");

    let Some(first_request) = requests.first() else {
        return false;
    };

    let probe = probe_request_dedicated(cli, first_request, 0).await;
    if execution_mode_from_probe(probe.single_connect_supported)
        == PostProbeExecutionMode::Multiplexed
    {
        log::info!("Server supports single connection mode - using multiplexed connections");
        true
    } else {
        log::info!("Server did not confirm single connection mode - using dedicated connections");
        false
    }
}

/// Entry point for executing a batch file
///
/// This function handles servers that may or may not support single connection mode.
/// If load testing mode is enabled, this function delegates to `execute_load_test`.
pub async fn execute_batch(cli: &Cli, batch: &BatchFile) -> anyhow::Result<Vec<RequestResult>> {
    if let Some(description) = &batch.metadata.description {
        log::info!("Executing batch: {description}");
        println!("Batch: {description}");
    }

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test(cli, batch, load_config).await;
    }

    let request_count = batch.requests.len();
    log::info!("Processing {request_count} requests (parallel: {})", batch.metadata.parallel);

    if batch.metadata.parallel {
        execute_parallel(cli, &batch.requests).await
    } else {
        let connection = establish_connection(cli).await?;
        execute_sequential(cli, connection, &batch.requests).await
    }
}

/// Handles load test execution from a batch file
async fn execute_batch_load_test(
    cli: &Cli,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
) -> anyhow::Result<Vec<RequestResult>> {
    log::info!(
        "Load testing mode enabled: {} repetitions, max {} parallel",
        load_config.repetitions,
        load_config.max_parallel
    );
    println!(
        "\n=== Load Testing Mode ===\nRepetitions: {}\nMax parallel: {}\nTotal requests: {}",
        load_config.repetitions,
        load_config.max_parallel,
        load_config.repetitions * batch.requests.len()
    );

    let result = if probe_server_capability(cli, &batch.requests).await {
        execute_load_test(cli, &batch.requests, load_config).await?
    } else {
        run_dedicated_load_test(cli, &batch.requests, load_config).await
    };
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::{execution_mode_from_probe, PostProbeExecutionMode};

    #[test]
    fn test_probe_chooses_multiplexed_when_single_connect_supported() {
        assert_eq!(execution_mode_from_probe(true), PostProbeExecutionMode::Multiplexed);
    }

    #[test]
    fn test_probe_chooses_dedicated_when_single_connect_not_supported() {
        assert_eq!(execution_mode_from_probe(false), PostProbeExecutionMode::Dedicated);
    }
}
