use tacacsrs_config::TacacsPlusServer;
use tacacsrs_networking::config_connect::ConnectOptions;

use crate::connection::Connection;

use super::dedicated::{
    execute_requests_dedicated, probe_single_connect, probe_single_connect_supported,
    run_dedicated_load_test,
};
use super::multiplexed::{
    execute_load_test_multiplexed, execute_parallel_multiplexed, execute_sequential_multiplexed,
};
use super::super::progress::print_load_test_summary;
use super::super::types::{BatchFile, LoadTestConfig, RequestResult};

enum ExecutionMode {
    Multiplexed(Option<Connection>),
    Dedicated,
}

/// Determines the execution mode for the batch.
///
/// When `dedicated` is `true`, the probe is skipped and dedicated mode is used
/// unconditionally. Otherwise a lightweight accounting record is sent via a
/// dedicated connection to check whether the server echoes
/// `TAC_PLUS_SINGLE_CONNECT_FLAG`. Non-load batches reuse the successful
/// probe stream by upgrading it into the multiplexed connection.
async fn determine_execution_mode(
    server: &TacacsPlusServer,
    dedicated: bool,
    upgrade_probe: bool,
    options: &ConnectOptions,
) -> ExecutionMode {
    if dedicated {
        log::info!("Dedicated mode forced by CLI flag — skipping single-connection probe");
        return ExecutionMode::Dedicated;
    }

    log::info!("Probing server for single-connection support via dedicated connection");
    if upgrade_probe {
        if let Some(connection) = probe_single_connect(server, options).await {
            ExecutionMode::Multiplexed(Some(connection))
        } else {
            ExecutionMode::Dedicated
        }
    } else if probe_single_connect_supported(server, options).await {
        ExecutionMode::Multiplexed(None)
    } else {
        ExecutionMode::Dedicated
    }
}

/// Entry point for executing a batch file over a direct server connection.
///
/// Unless `dedicated` is `true`, a lightweight probe is sent first to detect
/// single-connection support. The result decides whether batch requests use
/// multiplexed or dedicated connections; normal multiplexed batches reuse the
/// probe stream instead of reconnecting.
pub async fn execute_batch(
    server: &TacacsPlusServer,
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

    let execution_mode =
        determine_execution_mode(server, dedicated, batch.metadata.load_test.is_none(), options)
            .await;

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test(server, batch, load_config, execution_mode, options).await;
    }

    let request_count = batch.requests.len();
    log::info!("Processing {request_count} requests (parallel: {})", batch.metadata.parallel);

    let results = match execution_mode {
        ExecutionMode::Multiplexed(Some(connection)) => {
            if batch.metadata.parallel {
                execute_parallel_multiplexed(connection, &batch.requests).await?
            } else {
                execute_sequential_multiplexed(connection, &batch.requests).await?
            }
        }
        ExecutionMode::Multiplexed(None) => {
            log::warn!(
                "Multiplexed mode was selected without an upgraded probe connection; falling back to dedicated connections"
            );
            execute_requests_dedicated(server, &batch.requests, batch.metadata.parallel, options)
                .await
        }
        ExecutionMode::Dedicated => {
            log::info!(
                "Executing {request_count} requests with dedicated connections (parallel: {})",
                batch.metadata.parallel,
            );
            execute_requests_dedicated(server, &batch.requests, batch.metadata.parallel, options)
                .await
        }
    };

    Ok(results)
}

/// Handles load test execution from a batch file
///
/// The execution mode has already been determined by `determine_execution_mode`.
async fn execute_batch_load_test(
    server: &TacacsPlusServer,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
    execution_mode: ExecutionMode,
    options: &ConnectOptions,
) -> anyhow::Result<Vec<RequestResult>> {
    let mode_label = match execution_mode {
        ExecutionMode::Multiplexed(_) => "Multiplexed Connections",
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
        ExecutionMode::Multiplexed(_) => {
            execute_load_test_multiplexed(server, &batch.requests, load_config, options).await?
        }
        ExecutionMode::Dedicated => {
            run_dedicated_load_test(server, &batch.requests, load_config, options).await
        }
    };
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}
