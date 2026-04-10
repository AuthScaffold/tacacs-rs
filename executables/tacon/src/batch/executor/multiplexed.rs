use anyhow::Context;
use futures::future::join_all;

use tacacsrs_config::ResolvedServer;
use tacacsrs_networking::config_connect::ConnectOptions;
use tacacsrs_networking::session::Session;

use crate::connection::{establish_connection, Connection};

use super::common::{execute_single_request, load_test_iterations, run_load_test};
use super::super::types::{BatchRequest, LoadTestConfig, LoadTestResult, RequestResult};

/// Executes requests sequentially on a multiplexed connection
///
/// The caller has already confirmed single-connection support via the probe,
/// so every request reuses the same connection without reconnect checks.
pub(super) async fn execute_sequential_multiplexed(
    connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    log::info!("Executing {} requests sequentially on multiplexed connection", requests.len());

    let mut results = Vec::with_capacity(requests.len());

    for (index, request) in requests.iter().enumerate() {
        log::info!("Executing request {}/{}", index + 1, requests.len());

        let session = connection
            .create_session_optional_id(request.session_id())
            .await
            .context("Failed to create session for batch request")?;

        if let Some(session_id) = request.session_id() {
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

/// Executes requests in parallel on a multiplexed connection
pub(super) async fn execute_parallel_multiplexed(
    connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    log::info!("Executing {} requests in parallel on multiplexed connection", requests.len());

    let mut session_futures = Vec::with_capacity(requests.len());
    for request in requests {
        session_futures.push(connection.create_session_optional_id(request.session_id()));
    }

    let sessions: Vec<Session> = join_all(session_futures)
        .await
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result.with_context(|| format!("Failed to create session for request {}", index + 1))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let futures: Vec<_> = requests
        .iter()
        .zip(sessions.iter())
        .enumerate()
        .map(|(index, (request, session))| async move {
            log::info!("Starting parallel request {}", index + 1);
            let result = execute_single_request(session, request).await;
            RequestResult {
                index,
                request_type: request.type_name(),
                result,
            }
        })
        .collect();

    Ok(join_all(futures).await)
}

/// Executes a load test using multiplexed connections with controlled concurrency
///
/// Each iteration opens a new multiplexed connection, creates a session, and
/// sends the request. The test stops immediately on the first failure.
pub(super) async fn execute_load_test_multiplexed(
    server: &ResolvedServer,
    requests: &[BatchRequest],
    config: &LoadTestConfig,
) -> anyhow::Result<LoadTestResult> {
    let total_requests = requests.len() * config.repetitions;

    println!("Starting load test with {total_requests} total requests...\n");

    let server = server.clone();
    Ok(run_load_test(
        total_requests,
        load_test_iterations(requests, config.repetitions),
        config.max_parallel,
        move |rep, idx, request| {
            let server = server.clone();
            async move { execute_load_test_single(&server, request, rep, idx).await }
        },
    )
    .await)
}

/// Executes a single load test iteration on a new multiplexed connection
async fn execute_load_test_single(
    server: &ResolvedServer,
    request: &BatchRequest,
    rep: usize,
    idx: usize,
) -> Result<(), String> {
    let connection = establish_connection(server, &ConnectOptions::default())
        .await
        .map_err(|error| {
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
