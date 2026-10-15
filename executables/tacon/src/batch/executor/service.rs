//! Service-mode (agent IPC) batch orchestration.
//!
//! This module establishes the persistent IPC backend and delegates request
//! scheduling and outcome formatting to the shared engine in [`super::common`].

use crate::backend::{connect_service, Backend};

use super::common::{announce_batch, finish_load_test, run_batch_load_test, run_requests};
use super::super::types::{BatchFile, LoadTestConfig, RequestResult};

/// Runs a batch file through the central agent over its IPC channel.
///
/// # Errors
///
/// Returns an error if the service cannot be reached or if a load test records
/// a failure.
pub(crate) async fn execute_batch_via_service(
    endpoint: &str,
    batch: &BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    let backend = Backend::Service(connect_service(endpoint).await?);

    announce_batch(batch);

    if let Some(load_config) = &batch.metadata.load_test {
        return run_service_load_test(&backend, batch, load_config).await;
    }

    let request_count = batch.requests.len();
    log::info!(
        "Processing {request_count} requests through central service (parallel: {})",
        batch.metadata.parallel
    );

    Ok(run_requests(&backend, &batch.requests, batch.metadata.parallel).await)
}

/// Runs a load test through the central agent.
async fn run_service_load_test(
    backend: &Backend,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
) -> anyhow::Result<Vec<RequestResult>> {
    log::info!(
        "Service load testing mode enabled: {} repetitions, max {} parallel",
        load_config.repetitions,
        load_config.max_parallel
    );
    println!(
        "\n=== Load Testing Mode (Central Service) ===\nRepetitions: {}\nMax parallel: {}\nTotal requests: {}",
        load_config.repetitions,
        load_config.max_parallel,
        load_config.repetitions * batch.requests.len()
    );

    finish_load_test(run_batch_load_test(backend, &batch.requests, load_config).await)
}
