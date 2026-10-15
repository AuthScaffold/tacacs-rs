//! Direct-mode batch orchestration.
//!
//! This module selects the direct execution mode (multiplexed or dedicated),
//! establishes the backend, and delegates request scheduling and outcome
//! formatting to the shared engine in [`super::common`].

use tacacsrs_config::TacacsPlusServer;
use tacacsrs_config::prepare::PrepareOptions;

use super::common::{announce_batch, finish_load_test, run_batch_load_test, run_requests};
use super::dedicated::{connection_failure_results, establish_dedicated_backend};
use super::multiplexed::establish_multiplexed_backend;
use super::super::types::{BatchFile, LoadTestConfig, RequestResult};

#[derive(Clone, Copy)]
enum ExecutionMode {
    Multiplexed,
    Dedicated,
}

impl ExecutionMode {
    const fn label(self) -> &'static str {
        match self {
            Self::Multiplexed => "Multiplexed Connections",
            Self::Dedicated => "Dedicated Connections",
        }
    }
}

/// Selects the direct execution mode.
///
/// A `--dedicated` flag forces dedicated mode. Otherwise the server's
/// single-connection setting decides between the adaptive and dedicated paths.
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
/// Unless `dedicated` is `true`, the server configuration decides whether batch
/// requests use the adaptive single-connection path or dedicated streams.
///
/// # Errors
///
/// Returns an error if the connection fails or if a load test records a failure.
pub(crate) async fn execute_batch(
    server: &TacacsPlusServer,
    dedicated: bool,
    batch: &BatchFile,
    options: PrepareOptions,
) -> anyhow::Result<Vec<RequestResult>> {
    announce_batch(batch);

    if batch.requests.is_empty() {
        return Ok(vec![]);
    }

    let mode = determine_execution_mode(dedicated, server.single_connection);

    if let Some(load_config) = &batch.metadata.load_test {
        return run_direct_load_test(server, batch, load_config, mode, options).await;
    }

    let request_count = batch.requests.len();
    log::info!("Processing {request_count} requests (parallel: {})", batch.metadata.parallel);

    let results = match mode {
        ExecutionMode::Multiplexed => {
            let backend = establish_multiplexed_backend(server, options).await?;
            run_requests(&backend, &batch.requests, batch.metadata.parallel).await
        }
        ExecutionMode::Dedicated => {
            log::info!(
                "Running {request_count} requests with dedicated connections (parallel: {})",
                batch.metadata.parallel,
            );
            match establish_dedicated_backend(server, options).await {
                Ok(backend) => {
                    run_requests(&backend, &batch.requests, batch.metadata.parallel).await
                }
                Err(error) => connection_failure_results(&batch.requests, &error),
            }
        }
    };

    Ok(results)
}

/// Runs a load test from a batch file over the selected direct mode.
async fn run_direct_load_test(
    server: &TacacsPlusServer,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
    mode: ExecutionMode,
    options: PrepareOptions,
) -> anyhow::Result<Vec<RequestResult>> {
    let mode_label = mode.label();
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

    let backend = match mode {
        ExecutionMode::Multiplexed => establish_multiplexed_backend(server, options).await?,
        ExecutionMode::Dedicated => establish_dedicated_backend(server, options).await?,
    };

    finish_load_test(run_batch_load_test(&backend, &batch.requests, load_config).await)
}

#[cfg(test)]
mod tests {
    use super::{determine_execution_mode, ExecutionMode};

    #[test]
    fn dedicated_flag_forces_dedicated_mode() {
        assert!(matches!(determine_execution_mode(true, true), ExecutionMode::Dedicated));
        assert!(matches!(determine_execution_mode(true, false), ExecutionMode::Dedicated));
    }

    #[test]
    fn single_connection_selects_multiplexed_when_not_forced() {
        assert!(matches!(determine_execution_mode(false, true), ExecutionMode::Multiplexed));
        assert!(matches!(determine_execution_mode(false, false), ExecutionMode::Dedicated));
    }
}
