use tacacsrs_config::TacacsPlusServer;
use tacacsrs_networking::config_connect::ConnectOptions;

use crate::connection::Connection;

use super::dedicated::{execute_requests_dedicated, probe_single_connect, run_dedicated_load_test};
use super::multiplexed::{
    execute_load_test_multiplexed, execute_parallel_multiplexed, execute_sequential_multiplexed,
};
use super::super::progress::print_load_test_summary;
use super::super::types::{BatchFile, LoadTestConfig, RequestResult};

enum ExecutionMode {
    Multiplexed,
    Dedicated,
}

/// Determines the execution mode for the batch.
///
/// When `dedicated` is `true`, the probe is skipped and dedicated mode is used
/// unconditionally. Otherwise the probe result decides whether the batch can
/// use multiplexed mode.
fn determine_execution_mode(dedicated: bool, single_connect_supported: bool) -> ExecutionMode {
    if dedicated {
        log::info!("Dedicated mode forced by CLI flag — skipping single-connection probe");
        return ExecutionMode::Dedicated;
    }

    if single_connect_supported {
        ExecutionMode::Multiplexed
    } else {
        ExecutionMode::Dedicated
    }
}

/// Entry point for executing a batch file over a direct server connection.
///
/// Unless `dedicated` is `true`, a lightweight probe is sent first to detect
/// single-connection support. The result decides whether batch requests use
/// multiplexed or dedicated connections. Normal multiplexed batches explicitly
/// upgrade the successful probe stream instead of reconnecting.
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

    let mut probe = if dedicated {
        None
    } else {
        log::info!("Probing server for single-connection support via dedicated connection");
        probe_single_connect(server, options).await
    };
    let execution_mode = determine_execution_mode(
        dedicated,
        probe.as_ref().is_some_and(|p| p.single_connect_supported),
    );

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test(server, batch, load_config, execution_mode, options).await;
    }

    let request_count = batch.requests.len();
    log::info!("Processing {request_count} requests (parallel: {})", batch.metadata.parallel);

    let results = match execution_mode {
        ExecutionMode::Multiplexed => {
            let Some(probe_connection) = probe.take().and_then(|probe| probe.connection) else {
                anyhow::bail!("Multiplexed mode selected without a successful probe connection");
            };
            let connection = Connection::from_inner(probe_connection.upgrade());
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
