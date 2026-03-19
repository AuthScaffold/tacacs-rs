//! Batch execution logic
//!
//! This module contains the execution strategies for batch requests:
//! sequential, parallel, and load testing modes.

use anyhow::Context;
use futures::future::join_all;
use futures::stream::{self, StreamExt};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tacacsrs_agent_client::{AccountingOperation, IpcEndpoint, ServiceClient};

use tacacsrs_networking::session::Session;
use tacacsrs_networking::{DedicatedConnection, SingleConnectionState};

use crate::cli::Cli;
use crate::commands::accounting::{build_accounting_request, send_accounting_request};
use crate::connection::{establish_connection, Connection};

use super::progress::{print_load_test_summary, ProgressConfig, ProgressTracker};
use super::types::{BatchRequest, LoadTestConfig, LoadTestResult, RequestResult};

fn service_client(cli: &Cli) -> anyhow::Result<ServiceClient> {
    let endpoint = cli
        .service_endpoint
        .as_deref()
        .context("Service endpoint is required for service mode")?;
    let endpoint = IpcEndpoint::from_str(endpoint).context("Invalid service endpoint")?;
    Ok(ServiceClient::new(endpoint))
}

fn to_service_accounting_request(request: &super::types::AccountingRequest) -> AccountingOperation {
    AccountingOperation {
        user: request.user.clone(),
        port: request.port.clone(),
        remote_address: request.rem_addr.clone(),
        command: request.cmd.clone(),
        command_arguments: request.cmd_args.clone(),
    }
}

fn validate_service_mode_request(request: &BatchRequest) -> Result<(), String> {
    match request {
        BatchRequest::Accounting(req)
            if req.custom_flags.custom_flag_1
                || req.custom_flags.custom_flag_2
                || req.session_id.is_some() =>
        {
            Err(
                "Central TACACS+ service mode does not support custom TACACS+ flags or client-specified session IDs"
                    .to_owned(),
            )
        }
        _ => Ok(()),
    }
}

/// Executes a single batch request on a session
pub async fn execute_single_request(
    session: &Session,
    request: &BatchRequest,
) -> Result<String, String> {
    match request {
        BatchRequest::Accounting(req) => {
            let cmd_args = if req.cmd_args.is_empty() {
                None
            } else {
                Some(&req.cmd_args)
            };

            let custom_flags = req.custom_flags.to_tacacs_flags();

            match send_accounting_request(
                session,
                &req.user,
                &req.port,
                &req.rem_addr,
                &req.cmd,
                cmd_args,
                custom_flags,
            )
            .await
            {
                Ok(response) => Ok(format!("Accounting success: {response:?}")),
                Err(e) => Err(format!("Accounting failed: {e}")),
            }
        }

        BatchRequest::Authentication(req) => {
            // TODO: Implement authentication
            log::warn!("Authentication not yet implemented for user: {}", req.user);
            Err(format!("Authentication not yet implemented (user: {})", req.user))
        }

        BatchRequest::Authorization(req) => {
            // TODO: Implement authorization
            log::warn!("Authorization not yet implemented for user: {}", req.user);
            Err(format!("Authorization not yet implemented (user: {})", req.user))
        }
    }
}

async fn execute_single_request_via_service(
    client: &ServiceClient,
    request: &BatchRequest,
) -> Result<String, String> {
    validate_service_mode_request(request)?;

    match request {
        BatchRequest::Accounting(req) => client
            .send_accounting(to_service_accounting_request(req))
            .await
            .map(|response| format!("Accounting success: {response:?}"))
            .map_err(|error| format!("Accounting failed: {error}")),
        BatchRequest::Authentication(req) => {
            log::warn!("Authentication not yet implemented for user: {}", req.user);
            Err(format!("Authentication not yet implemented (user: {})", req.user))
        }
        BatchRequest::Authorization(req) => {
            log::warn!("Authorization not yet implemented for user: {}", req.user);
            Err(format!("Authorization not yet implemented (user: {})", req.user))
        }
    }
}

/// Executes requests sequentially, one at a time
///
/// If the server doesn't support single connection mode, a new connection
/// is established for each subsequent request.
pub async fn execute_sequential(
    cli: &Cli,
    mut connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    let mut results = Vec::with_capacity(requests.len());

    for (index, request) in requests.iter().enumerate() {
        log::info!("Executing request {}/{}", index + 1, requests.len());

        // Check if we need a new connection (after first request, if single connection not supported)
        if index > 0 {
            connection = maybe_reconnect(cli, connection, index).await?;
        }

        let custom_session_id = request.session_id();
        let session = connection
            .create_session_optional_id(custom_session_id)
            .await
            .context("Failed to create session for batch request")?;

        if let Some(sid) = custom_session_id {
            log::info!("Using custom session ID: {sid}");
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
            // This shouldn't happen in sequential mode after the first request
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
pub async fn execute_parallel(
    cli: &Cli,
    connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    if requests.is_empty() {
        return Ok(vec![]);
    }

    // Execute the first request to determine single connection mode support
    let first_request = &requests[0];
    log::info!("Executing first request to determine single connection mode support");

    let first_session = connection
        .create_session_optional_id(first_request.session_id())
        .await
        .context("Failed to create session for first batch request")?;

    let first_result = execute_single_request(&first_session, first_request).await;
    let mut results = vec![RequestResult {
        index: 0,
        request_type: first_request.type_name(),
        result: first_result,
    }];

    // If only one request, we're done
    if requests.len() == 1 {
        return Ok(results);
    }

    let remaining_requests = &requests[1..];

    // Check if single connection mode is supported
    let single_connection_supported =
        matches!(connection.single_connection_state().await, SingleConnectionState::Supported);

    if single_connection_supported {
        results.extend(execute_parallel_single_connection(connection, remaining_requests).await?);
    } else {
        results.extend(execute_parallel_multi_connection(cli, remaining_requests).await);
    }

    // Sort results by index to maintain order
    results.sort_by_key(|r| r.index);

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

    // Create all sessions upfront on the same connection
    let mut session_futures = Vec::with_capacity(requests.len());
    for request in requests {
        session_futures.push(connection.create_session_optional_id(request.session_id()));
    }

    let sessions: Vec<Session> = join_all(session_futures)
        .await
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.with_context(|| format!("Failed to create session for request {}", i + 2)))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Execute all requests in parallel
    let futures: Vec<_> = requests
        .iter()
        .zip(sessions.iter())
        .enumerate()
        .map(|(i, (request, session))| {
            let index = i + 1; // Offset by 1 since we already did index 0
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

/// Executes requests in parallel, each with its own connection
async fn execute_parallel_multi_connection(
    cli: &Cli,
    requests: &[BatchRequest],
) -> Vec<RequestResult> {
    log::info!(
        "Server does not support single connection mode. Executing {} requests with separate connections",
        requests.len()
    );

    let futures: Vec<_> = requests
        .iter()
        .enumerate()
        .map(|(i, request)| {
            let index = i + 1; // Offset by 1 since we already did index 0
            let cli = cli.clone();
            async move {
                log::info!("Establishing new connection for request {}", index + 1);
                execute_request_with_new_connection(&cli, request, index).await
            }
        })
        .collect();

    join_all(futures).await
}

/// Executes a single request by establishing a new connection
async fn execute_request_with_new_connection(
    cli: &Cli,
    request: &BatchRequest,
    index: usize,
) -> RequestResult {
    let conn = match establish_connection(cli).await {
        Ok(c) => c,
        Err(e) => {
            return RequestResult {
                index,
                request_type: request.type_name(),
                result: Err(format!("Failed to establish connection: {e}")),
            };
        }
    };

    let session = match conn.create_session_optional_id(request.session_id()).await {
        Ok(s) => s,
        Err(e) => {
            return RequestResult {
                index,
                request_type: request.type_name(),
                result: Err(format!("Failed to create session: {e}")),
            };
        }
    };

    let result = execute_single_request(&session, request).await;
    RequestResult {
        index,
        request_type: request.type_name(),
        result,
    }
}

/// Executes a load test by repeating all requests with controlled concurrency
///
/// This function runs all requests multiple times (based on `config.repetitions`)
/// with a maximum of `config.max_parallel` concurrent requests. The test stops
/// immediately on the first failure.
pub async fn execute_load_test(
    cli: &Cli,
    connection: Connection,
    requests: &[BatchRequest],
    config: &LoadTestConfig,
) -> anyhow::Result<LoadTestResult> {
    let total_requests = requests.len() * config.repetitions;
    let start_time = Instant::now();

    // Probe server for single-connection support
    probe_server_capability(&connection, requests).await?;

    println!("Starting load test with {total_requests} total requests...\n");

    // Set up progress tracking
    let tracker = ProgressTracker::new(ProgressConfig {
        total_requests,
        ..Default::default()
    });

    // Build a lazy iterator over all request iterations
    let all_iterations = (0..config.repetitions).flat_map(|rep| {
        requests
            .iter()
            .enumerate()
            .map(move |(idx, req)| (rep, idx, req))
    });

    // Execute with controlled concurrency
    let results =
        execute_load_test_iterations(cli, all_iterations, &tracker, config.max_parallel).await;

    // Wait for progress display to finish
    let failure_msg = tracker.finish().await;

    build_load_test_result(start_time, total_requests, &results, failure_msg)
}

/// Probes the server to check for single-connection support
async fn probe_server_capability(
    connection: &Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<()> {
    log::info!("Probing server for single-connection support...");

    let probe_session = connection
        .create_session_optional_id(None)
        .await
        .context("Failed to create probe session")?;

    if let Some(first_request) = requests.first() {
        let _ = execute_single_request(&probe_session, first_request).await;
    }

    let single_connection_supported =
        matches!(connection.single_connection_state().await, SingleConnectionState::Supported);

    if single_connection_supported {
        log::info!("Server supports single connection mode - reusing connections where possible");
    } else {
        log::info!("Server does not support single connection mode - using separate connections");
    }

    Ok(())
}

/// Executes load test iterations with controlled concurrency
async fn execute_load_test_iterations<'a, I>(
    cli: &Cli,
    iterations: I,
    tracker: &ProgressTracker,
    max_parallel: usize,
) -> Vec<bool>
where
    I: Iterator<Item = (usize, usize, &'a BatchRequest)>,
{
    let cli = cli.clone();

    stream::iter(iterations)
        .map(|(rep, idx, request)| {
            let cli = cli.clone();
            let completed = tracker.completed.clone();
            let failed = tracker.failed.clone();
            let first_failure = tracker.first_failure.clone();

            async move {
                // Check if we should stop due to a previous failure
                if failed.load(std::sync::atomic::Ordering::Relaxed) {
                    return false;
                }

                // Execute the request with a new connection
                match execute_load_test_single(&cli, request, rep, idx).await {
                    Ok(()) => {
                        completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        true
                    }
                    Err(e) => {
                        if !failed.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            let mut failure = first_failure.lock().await;
                            *failure = Some(e);
                        }
                        false
                    }
                }
            }
        })
        .buffer_unordered(max_parallel)
        .collect()
        .await
}

/// Executes a single load test iteration
async fn execute_load_test_single(
    cli: &Cli,
    request: &BatchRequest,
    rep: usize,
    idx: usize,
) -> Result<(), String> {
    let conn = establish_connection(cli)
        .await
        .map_err(|e| format!("Connection failed at rep {}, request {}: {}", rep + 1, idx + 1, e))?;

    let session = conn
        .create_session_optional_id(request.session_id())
        .await
        .map_err(|e| {
            format!("Session creation failed at rep {}, request {}: {}", rep + 1, idx + 1, e)
        })?;

    execute_single_request(&session, request)
        .await
        .map(|_| ())
        .map_err(|e| {
            format!(
                "Request failed at rep {}, request {} ({}): {}",
                rep + 1,
                idx + 1,
                request.type_name(),
                e
            )
        })
}

/// Builds the final load test result from execution data
#[allow(clippy::unnecessary_wraps)]
fn build_load_test_result(
    start_time: Instant,
    total_requests: usize,
    results: &[bool],
    failure_msg: Option<String>,
) -> anyhow::Result<LoadTestResult> {
    let duration = start_time.elapsed();
    let successful_requests = results.iter().filter(|&&r| r).count();
    let failed_requests = usize::from(failure_msg.is_some());
    #[allow(clippy::cast_precision_loss)]
    let requests_per_second = if duration.as_secs_f64() > 0.0 {
        successful_requests as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    Ok(LoadTestResult {
        total_requests,
        successful_requests,
        failed_requests,
        duration,
        first_failure: failure_msg,
        requests_per_second,
    })
}

pub async fn execute_batch_via_service(
    cli: &Cli,
    batch: &super::types::BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    let client = service_client(cli)?;

    if let Some(desc) = &batch.metadata.description {
        log::info!("Executing batch: {desc}");
        println!("Batch: {desc}");
    }

    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test_via_service(cli, batch, load_config).await;
    }

    let request_count = batch.requests.len();
    log::info!(
        "Processing {request_count} requests through central service (parallel: {})",
        batch.metadata.parallel
    );

    if batch.metadata.parallel {
        let futures: Vec<_> = batch
            .requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let client = client.clone();
                async move {
                    let result = execute_single_request_via_service(&client, request).await;
                    RequestResult {
                        index,
                        request_type: request.type_name(),
                        result,
                    }
                }
            })
            .collect();
        Ok(join_all(futures).await)
    } else {
        let mut results = Vec::with_capacity(batch.requests.len());
        for (index, request) in batch.requests.iter().enumerate() {
            let result = execute_single_request_via_service(&client, request).await;
            results.push(RequestResult {
                index,
                request_type: request.type_name(),
                result,
            });
        }
        Ok(results)
    }
}

async fn execute_batch_load_test_via_service(
    cli: &Cli,
    batch: &super::types::BatchFile,
    load_config: &LoadTestConfig,
) -> anyhow::Result<Vec<RequestResult>> {
    let client = Arc::new(service_client(cli)?);

    log::info!(
        "Service load testing mode enabled: {} repetitions, max {} parallel",
        load_config.repetitions,
        load_config.max_parallel
    );
    println!(
        "\n=== Load Testing Mode ===\nRepetitions: {}\nMax parallel: {}\nTotal requests: {}",
        load_config.repetitions,
        load_config.max_parallel,
        load_config.repetitions * batch.requests.len()
    );

    let total_requests = batch.requests.len() * load_config.repetitions;
    let start_time = Instant::now();
    let tracker = ProgressTracker::new(ProgressConfig {
        total_requests,
        ..Default::default()
    });

    let results = stream::iter((0..load_config.repetitions).flat_map(|rep| {
        batch
            .requests
            .iter()
            .enumerate()
            .map(move |(idx, req)| (rep, idx, req))
    }))
    .map(|(rep, idx, request)| {
        let client = Arc::clone(&client);
        let completed = tracker.completed.clone();
        let failed = tracker.failed.clone();
        let first_failure = tracker.first_failure.clone();

        async move {
            if failed.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }

            match execute_single_request_via_service(client.as_ref(), request).await {
                Ok(_) => {
                    completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    true
                }
                Err(error) => {
                    if !failed.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        let mut failure = first_failure.lock().await;
                        *failure = Some(format!(
                            "Request failed at rep {}, request {} ({}): {}",
                            rep + 1,
                            idx + 1,
                            request.type_name(),
                            error
                        ));
                    }
                    false
                }
            }
        }
    })
    .buffer_unordered(load_config.max_parallel)
    .collect::<Vec<_>>()
    .await;

    let failure_msg = tracker.finish().await;
    let result = build_load_test_result(start_time, total_requests, &results, failure_msg)?;
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}

/// Entry point for executing a batch file
///
/// This function handles servers that may or may not support single connection mode.
/// If load testing mode is enabled, this function delegates to `execute_load_test`.
pub async fn execute_batch(
    cli: &Cli,
    connection: Connection,
    batch: &super::types::BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    if let Some(desc) = &batch.metadata.description {
        log::info!("Executing batch: {desc}");
        println!("Batch: {desc}");
    }

    // Check if load testing mode is enabled
    if let Some(load_config) = &batch.metadata.load_test {
        return execute_batch_load_test(cli, connection, batch, load_config).await;
    }

    let request_count = batch.requests.len();
    log::info!("Processing {request_count} requests (parallel: {})", batch.metadata.parallel);

    if batch.metadata.parallel {
        execute_parallel(cli, connection, &batch.requests).await
    } else {
        execute_sequential(cli, connection, &batch.requests).await
    }
}

/// Handles load test execution from a batch file
async fn execute_batch_load_test(
    cli: &Cli,
    connection: Connection,
    batch: &super::types::BatchFile,
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

    let result = execute_load_test(cli, connection, &batch.requests, load_config).await?;
    print_load_test_summary(&result);

    // Return empty results since load test has its own summary
    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Dedicated-connection batch execution
// ---------------------------------------------------------------------------

/// Executes a single batch request using a dedicated connection (no background
/// tasks, no session multiplexing).
async fn execute_single_request_dedicated(
    cli: &Cli,
    request: &BatchRequest,
) -> Result<String, String> {
    let server_addr = cli
        .server_addr
        .as_deref()
        .ok_or_else(|| "--server-addr is required for --dedicated mode".to_owned())?;

    match request {
        BatchRequest::Accounting(req) => {
            let stream = tacacsrs_networking::helpers::connect_tcp(server_addr)
                .await
                .map_err(|e| format!("Connection failed: {e}"))?;

            let obfuscation_key = cli.obfuscation_key.as_ref().map(String::as_bytes);
            let mut conn = DedicatedConnection::new(stream, obfuscation_key);

            let cmd_args = if req.cmd_args.is_empty() {
                None
            } else {
                Some(&req.cmd_args)
            };
            let tacacs_request =
                build_accounting_request(&req.user, &req.port, &req.rem_addr, &req.cmd, cmd_args);

            conn.send_accounting(tacacs_request, req.custom_flags.to_tacacs_flags())
                .await
                .map(|result| format!("Accounting success: {:?}", result.reply))
                .map_err(|e| format!("Accounting failed: {e}"))
        }
        BatchRequest::Authentication(req) => {
            Err(format!("Authentication not yet implemented (user: {})", req.user))
        }
        BatchRequest::Authorization(req) => {
            Err(format!("Authorization not yet implemented (user: {})", req.user))
        }
    }
}

/// Executes all batch requests using dedicated connections.
///
/// Each request opens and closes its own TCP connection with no session
/// multiplexing and no background tasks.  Supports sequential, parallel,
/// and load-test modes.
pub async fn execute_batch_dedicated(
    cli: &Cli,
    batch: &super::types::BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    if let Some(desc) = &batch.metadata.description {
        log::info!("Executing batch (dedicated connections): {desc}");
        println!("Batch: {desc}");
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
        let futures: Vec<_> = batch
            .requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let cli = cli.clone();
                async move {
                    RequestResult {
                        index,
                        request_type: request.type_name(),
                        result: execute_single_request_dedicated(&cli, request).await,
                    }
                }
            })
            .collect();
        Ok(join_all(futures).await)
    } else {
        let mut results = Vec::with_capacity(request_count);
        for (index, request) in batch.requests.iter().enumerate() {
            log::info!("Executing request {}/{request_count}", index + 1);
            results.push(RequestResult {
                index,
                request_type: request.type_name(),
                result: execute_single_request_dedicated(cli, request).await,
            });
        }
        Ok(results)
    }
}

async fn execute_batch_load_test_dedicated(
    cli: &Cli,
    batch: &super::types::BatchFile,
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

    let total_requests = batch.requests.len() * load_config.repetitions;
    let start_time = Instant::now();
    let tracker = ProgressTracker::new(ProgressConfig {
        total_requests,
        ..Default::default()
    });

    let all_iterations = (0..load_config.repetitions).flat_map(|rep| {
        batch
            .requests
            .iter()
            .enumerate()
            .map(move |(idx, req)| (rep, idx, req))
    });

    let cli = cli.clone();
    let results: Vec<bool> = stream::iter(all_iterations)
        .map(|(rep, idx, request)| {
            let cli = cli.clone();
            let completed = tracker.completed.clone();
            let failed = tracker.failed.clone();
            let first_failure = tracker.first_failure.clone();

            async move {
                if failed.load(std::sync::atomic::Ordering::Relaxed) {
                    return false;
                }

                match execute_single_request_dedicated(&cli, request).await {
                    Ok(_) => {
                        completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        true
                    }
                    Err(e) => {
                        let msg =
                            format!("Request failed at rep {}, request {}: {e}", rep + 1, idx + 1,);
                        if !failed.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            let mut failure = first_failure.lock().await;
                            *failure = Some(msg);
                        }
                        false
                    }
                }
            }
        })
        .buffer_unordered(load_config.max_parallel)
        .collect()
        .await;

    let failure_msg = tracker.finish().await;
    let result = build_load_test_result(start_time, total_requests, &results, failure_msg)?;
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_service_mode_request;
    use crate::batch::types::{AccountingRequest, BatchRequest, CustomFlags};

    #[test]
    fn test_service_mode_rejects_custom_flags_and_session_ids_in_batch_requests() {
        let request = BatchRequest::Accounting(AccountingRequest {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            rem_addr: "127.0.0.1".to_owned(),
            cmd: "show".to_owned(),
            cmd_args: vec![],
            custom_flags: CustomFlags {
                custom_flag_1: true,
                custom_flag_2: false,
            },
            session_id: None,
        });
        assert!(validate_service_mode_request(&request).is_err());

        let request = BatchRequest::Accounting(AccountingRequest {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            rem_addr: "127.0.0.1".to_owned(),
            cmd: "show".to_owned(),
            cmd_args: vec![],
            custom_flags: CustomFlags::default(),
            session_id: Some(7),
        });
        assert!(validate_service_mode_request(&request).is_err());
    }
}
