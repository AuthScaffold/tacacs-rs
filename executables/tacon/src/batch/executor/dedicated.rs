use anyhow::Context;
use futures::future::join_all;

use tacacsrs_networking::DedicatedConnection;

use crate::cli::Cli;
use crate::commands::accounting::build_accounting_request;
use crate::connection::establish_stream;

use super::common::{load_test_iterations, run_load_test};
use super::super::progress::print_load_test_summary;
use super::super::types::{BatchFile, BatchRequest, LoadTestConfig, RequestResult};

pub(super) struct DedicatedProbeResult {
    pub request_result: RequestResult,
    pub single_connect_supported: bool,
}

/// Executes a single batch request using a dedicated connection (no background
/// tasks, no session multiplexing).
async fn execute_single_request_dedicated(
    cli: &Cli,
    request: &BatchRequest,
) -> Result<String, String> {
    match request {
        BatchRequest::Accounting(req) => {
            let stream = establish_stream(cli)
                .await
                .map_err(|error| format!("Connection failed: {error}"))?;

            let obfuscation_key = cli.obfuscation_key.as_ref().map(String::as_bytes);
            let mut connection = DedicatedConnection::new(stream, obfuscation_key);

            let cmd_args = if req.cmd_args.is_empty() {
                None
            } else {
                Some(&req.cmd_args)
            };
            let tacacs_request =
                build_accounting_request(&req.user, &req.port, &req.rem_addr, &req.cmd, cmd_args);

            connection
                .send_accounting(tacacs_request, req.custom_flags.to_tacacs_flags())
                .await
                .map(|result| format!("Accounting success: {:?}", result.reply))
                .map_err(|error| format!("Accounting failed: {error}"))
        }
        BatchRequest::Authentication(req) => {
            Err(format!("Authentication not yet implemented (user: {})", req.user))
        }
        BatchRequest::Authorization(req) => {
            Err(format!("Authorization not yet implemented (user: {})", req.user))
        }
    }
}

pub(super) async fn probe_request_dedicated(
    cli: &Cli,
    request: &BatchRequest,
    index: usize,
) -> DedicatedProbeResult {
    match request {
        BatchRequest::Accounting(req) => {
            let result = execute_accounting_request_dedicated(cli, req).await;
            DedicatedProbeResult {
                request_result: RequestResult {
                    index,
                    request_type: request.type_name(),
                    result: result
                        .as_ref()
                        .map(|exchange| format!("Accounting success: {:?}", exchange.reply))
                        .map_err(|error| format!("Accounting failed: {error}")),
                },
                single_connect_supported: result
                    .as_ref()
                    .is_ok_and(|exchange| exchange.single_connect_supported),
            }
        }
        _ => DedicatedProbeResult {
            request_result: RequestResult {
                index,
                request_type: request.type_name(),
                result: execute_single_request_dedicated(cli, request).await,
            },
            single_connect_supported: false,
        },
    }
}

pub(super) async fn execute_requests_dedicated(
    cli: &Cli,
    requests: &[BatchRequest],
    index_offset: usize,
    parallel: bool,
) -> Vec<RequestResult> {
    if parallel {
        let futures: Vec<_> = requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let cli = cli.clone();
                let index = index + index_offset;
                async move {
                    RequestResult {
                        index,
                        request_type: request.type_name(),
                        result: execute_single_request_dedicated(&cli, request).await,
                    }
                }
            })
            .collect();
        join_all(futures).await
    } else {
        let mut results = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            let index = index + index_offset;
            log::info!("Executing request {}/{}", index + 1, requests.len() + index_offset);
            results.push(RequestResult {
                index,
                request_type: request.type_name(),
                result: execute_single_request_dedicated(cli, request).await,
            });
        }
        results
    }
}

pub(super) async fn run_dedicated_load_test(
    cli: &Cli,
    requests: &[BatchRequest],
    load_config: &LoadTestConfig,
) -> super::super::types::LoadTestResult {
    let cli = cli.clone();
    run_load_test(
        requests.len() * load_config.repetitions,
        load_test_iterations(requests, load_config.repetitions),
        load_config.max_parallel,
        move |rep, idx, request| {
            let cli = cli.clone();
            async move {
                execute_single_request_dedicated(&cli, request)
                    .await
                    .map(|_| ())
                    .map_err(|error| {
                        format!("Request failed at rep {}, request {}: {error}", rep + 1, idx + 1)
                    })
            }
        },
    )
    .await
}

async fn execute_accounting_request_dedicated(
    cli: &Cli,
    req: &super::super::types::AccountingRequest,
) -> anyhow::Result<tacacsrs_networking::ExchangeResult> {
    let stream = establish_stream(cli).await.context("Connection failed")?;
    let obfuscation_key = cli.obfuscation_key.as_ref().map(String::as_bytes);
    let mut connection = DedicatedConnection::new(stream, obfuscation_key);

    let cmd_args = if req.cmd_args.is_empty() {
        None
    } else {
        Some(&req.cmd_args)
    };
    let tacacs_request =
        build_accounting_request(&req.user, &req.port, &req.rem_addr, &req.cmd, cmd_args);

    connection
        .send_accounting(tacacs_request, req.custom_flags.to_tacacs_flags())
        .await
}

/// Executes all batch requests using dedicated connections.
///
/// Each request opens and closes its own TCP/TLS transport connection with no session
/// multiplexing and no background tasks. Supports sequential, parallel,
/// and load-test modes.
pub async fn execute_batch_dedicated(
    cli: &Cli,
    batch: &BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    if let Some(description) = &batch.metadata.description {
        log::info!("Executing batch (dedicated connections): {description}");
        println!("Batch: {description}");
    }

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test_dedicated(cli, batch, load_config).await;
    }

    let request_count = batch.requests.len();
    log::info!(
        "Processing {request_count} requests with dedicated connections (parallel: {})",
        batch.metadata.parallel,
    );

    if batch.metadata.parallel {
        Ok(execute_requests_dedicated(cli, &batch.requests, 0, true).await)
    } else {
        Ok(execute_requests_dedicated(cli, &batch.requests, 0, false).await)
    }
}

async fn execute_batch_load_test_dedicated(
    cli: &Cli,
    batch: &BatchFile,
    load_config: &LoadTestConfig,
) -> anyhow::Result<Vec<RequestResult>> {
    log::info!(
        "Load testing mode (dedicated connections): {} repetitions, max {} parallel",
        load_config.repetitions,
        load_config.max_parallel,
    );
    println!(
        "\n=== Load Testing Mode (Dedicated Connections) ===\nRepetitions: {}\nMax parallel: {}\nTotal requests: {}",
        load_config.repetitions,
        load_config.max_parallel,
        load_config.repetitions * batch.requests.len(),
    );

    let result = run_dedicated_load_test(cli, &batch.requests, load_config).await;
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}
