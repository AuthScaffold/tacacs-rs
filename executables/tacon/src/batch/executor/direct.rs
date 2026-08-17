use tacacsrs_config::TacacsPlusServer;
use tacacsrs_networking::ConnectOptions;

use super::dedicated::{execute_requests_dedicated, run_dedicated_load_test};
use super::multiplexed::{
    execute_load_test_multiplexed, execute_parallel_multiplexed, execute_sequential_multiplexed,
};
use super::super::progress::print_load_test_summary;
use super::super::types::{BatchFile, LoadTestConfig, RequestResult};

enum ExecutionMode {
    Multiplexed,
    Dedicated,
}

/// Determines the run mode for the batch.
///
/// When `dedicated` is `true`, dedicated mode is used unconditionally.
/// Otherwise the server configuration decides whether the batch can use the
/// adaptive single-connection path.
fn determine_execution_mode(dedicated: bool, single_connection_enabled: bool) -> ExecutionMode {
    if dedicated {
        log::info!("Dedicated mode forced by CLI flag");
        return ExecutionMode::Dedicated;
    }

    if single_connection_enabled {
        ExecutionMode::Multiplexed
    } else {
        ExecutionMode::Dedicated
    }
}

/// Runs a batch file over a direct server connection.
///
/// Unless `dedicated` is `true`, the server configuration decides whether
/// batch requests use the adaptive single-connection path or dedicated streams.
pub async fn execute_batch(
    server: &TacacsPlusServer,
    dedicated: bool,
    batch: &BatchFile,
    options: &ConnectOptions,
) -> anyhow::Result<Vec<RequestResult>> {
    if let Some(description) = &batch.metadata.description {
        log::info!("Running batch: {description}");
        println!("Batch: {description}");
    }

    if batch.requests.is_empty() {
        return Ok(vec![]);
    }

    let execution_mode = determine_execution_mode(dedicated, server.single_connection);

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test(server, batch, load_config, execution_mode, options).await;
    }

    let request_count = batch.requests.len();
    log::info!("Processing {request_count} requests (parallel: {})", batch.metadata.parallel);

    let results = match execution_mode {
        ExecutionMode::Multiplexed => {
            let connection = crate::connection::establish_connection(server, options).await?;
            if batch.metadata.parallel {
                execute_parallel_multiplexed(connection, &batch.requests).await?
            } else {
                execute_sequential_multiplexed(connection, &batch.requests).await?
            }
        }
        ExecutionMode::Dedicated => {
            log::info!(
                "Running {request_count} requests with dedicated connections (parallel: {})",
                batch.metadata.parallel,
            );
            execute_requests_dedicated(server, &batch.requests, batch.metadata.parallel, options)
                .await
        }
    };

    Ok(results)
}

/// Runs a load test from a batch file.
///
/// The run mode is already set by `determine_execution_mode`.
async fn execute_batch_load_test(
    server: &TacacsPlusServer,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
    execution_mode: ExecutionMode,
    options: &ConnectOptions,
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
            execute_load_test_multiplexed(server, &batch.requests, load_config, options).await?
        }
        ExecutionMode::Dedicated => {
            run_dedicated_load_test(server, &batch.requests, load_config, options).await?
        }
    };
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}
