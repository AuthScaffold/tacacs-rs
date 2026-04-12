use anyhow::Context;

use tacacsrs_credentials::ResolvedServer;
use tacacsrs_networking::config_connect::ConnectOptions;

use crate::connection::establish_connection;

use super::dedicated::{execute_requests_dedicated, probe_single_connect, run_dedicated_load_test};
use super::multiplexed::{
    execute_load_test_multiplexed, execute_parallel_multiplexed, execute_sequential_multiplexed,
};
use super::super::progress::print_load_test_summary;
use super::super::types::{BatchFile, LoadTestConfig, RequestResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionMode {
    Multiplexed,
    Dedicated,
}

/// Determines the execution mode for the batch.
///
/// When `dedicated` is `true`, the probe is skipped and dedicated mode is used
/// unconditionally. Otherwise a lightweight accounting record is sent via a
/// dedicated connection to check whether the server echoes
/// `TAC_PLUS_SINGLE_CONNECT_FLAG`.
async fn determine_execution_mode(server: &ResolvedServer, dedicated: bool) -> ExecutionMode {
    if dedicated {
        log::info!("Dedicated mode forced by CLI flag — skipping single-connection probe");
        return ExecutionMode::Dedicated;
    }

    log::info!("Probing server for single-connection support via dedicated connection");
    if probe_single_connect(server).await {
        ExecutionMode::Multiplexed
    } else {
        ExecutionMode::Dedicated
    }
}

/// Entry point for executing a batch file over a direct server connection.
///
/// Unless `dedicated` is `true`, a lightweight probe is sent first to detect
/// single-connection support. The result decides whether batch requests use
/// multiplexed or dedicated connections.
pub async fn execute_batch(
    server: &ResolvedServer,
    dedicated: bool,
    batch: &BatchFile,
    options: &ConnectOptions,
) -> anyhow::Result<Vec<RequestResult>> {
    if let Some(description) = &batch.metadata.description {
        log::info!("Executing batch: {description}");
        println!("Batch: {description}");
    }

    if batch.requests.is_empty() {
        return Ok(vec![]);
    }

    let execution_mode = determine_execution_mode(server, dedicated).await;

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test(server, batch, load_config, execution_mode).await;
    }

    let request_count = batch.requests.len();
    log::info!("Processing {request_count} requests (parallel: {})", batch.metadata.parallel);

    let results = match execution_mode {
        ExecutionMode::Multiplexed => {
            let connection = establish_connection(server, options)
                .await
                .context("Failed to establish multiplexed connection after probe")?;

            if batch.metadata.parallel {
                execute_parallel_multiplexed(connection, &batch.requests).await?
            } else {
                execute_sequential_multiplexed(connection, &batch.requests).await?
            }
        }
        ExecutionMode::Dedicated => {
            log::info!(
                "Executing {request_count} requests with dedicated connections (parallel: {})",
                batch.metadata.parallel,
            );
            execute_requests_dedicated(server, &batch.requests, batch.metadata.parallel).await
        }
    };

    Ok(results)
}

/// Handles load test execution from a batch file
///
/// The execution mode has already been determined by `determine_execution_mode`.
async fn execute_batch_load_test(
    server: &ResolvedServer,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
    execution_mode: ExecutionMode,
) -> anyhow::Result<Vec<RequestResult>> {
    let mode_label = match execution_mode {
        ExecutionMode::Multiplexed => "Multiplexed Connections",
        ExecutionMode::Dedicated => "Dedicated Connections",
    };
    log::info!(
        "Load testing mode ({mode_label}): {} repetitions, max {} parallel",
        load_config.repetitions,
        load_config.max_parallel
    );
    println!(
        "\n=== Load Testing Mode ({mode_label}) ===\nRepetitions: {}\nMax parallel: {}\nTotal requests: {}",
        load_config.repetitions,
        load_config.max_parallel,
        load_config.repetitions * batch.requests.len()
    );

    let result = match execution_mode {
        ExecutionMode::Multiplexed => {
            execute_load_test_multiplexed(server, &batch.requests, load_config).await?
        }
        ExecutionMode::Dedicated => {
            run_dedicated_load_test(server, &batch.requests, load_config).await
        }
    };
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}
