use anyhow::Context;
use futures::future::join_all;

use tacacsrs_config::TacacsPlusServer;
use tacacsrs_networking::ConnectOptions;

use crate::connection::{establish_connection, Connection};

use super::common::{execute_single_request, load_test_iterations, run_load_test};
use super::super::types::{BatchRequest, LoadTestConfig, LoadTestResult, RequestResult};

/// Executes requests sequentially on a multiplexed connection
///
/// The first request may perform single-connection negotiation. Once the
/// server confirms support, later requests reuse the upgraded shared transport.
pub(super) async fn execute_sequential_multiplexed(
    connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    log::info!("Executing {} requests sequentially on multiplexed connection", requests.len());

    let mut results = Vec::with_capacity(requests.len());

    for (index, request) in requests.iter().enumerate() {
        log::info!("Executing request {}/{}", index + 1, requests.len());

        let result = execute_single_request(&connection, request).await;
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

    let futures: Vec<_> = requests
        .iter()
        .enumerate()
        .map(|(index, request)| {
            let connection = connection.clone();
            async move {
                log::info!("Starting parallel request {}", index + 1);
                let result = execute_single_request(&connection, request).await;
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

/// Executes a load test using multiplexed connections with controlled concurrency
///
/// The load test uses one adaptive connection for the whole run. The first
/// request may negotiate single-connection support; subsequent requests create
/// sessions from the same client and reuse the upgraded shared transport when
/// the server supports it. The test stops immediately on the first failure.
pub(super) async fn execute_load_test_multiplexed(
    server: &TacacsPlusServer,
    requests: &[BatchRequest],
    config: &LoadTestConfig,
    options: &ConnectOptions,
) -> anyhow::Result<LoadTestResult> {
    let total_requests = requests.len() * config.repetitions;

    println!("Starting load test with {total_requests} total requests...\n");

    let connection = establish_connection(server, options)
        .await
        .context("Failed to establish multiplexed TACACS+ connection for load test")?;

    Ok(run_load_test(
        total_requests,
        load_test_iterations(requests, config.repetitions),
        config.max_parallel,
        move |rep, idx, request| {
            let connection = connection.clone();
            async move { execute_load_test_single(&connection, request, rep, idx).await }
        },
    )
    .await)
}

/// Executes a single load test iteration on the shared multiplexed connection.
async fn execute_load_test_single(
    connection: &Connection,
    request: &BatchRequest,
    rep: usize,
    idx: usize,
) -> Result<(), String> {
    execute_single_request(connection, request)
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
