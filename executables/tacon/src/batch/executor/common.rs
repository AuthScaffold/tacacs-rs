use anyhow::Context;
use futures::stream::{self, StreamExt};
use std::future::Future;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tacacsrs_agent_client::{AccountingOperation, IpcEndpoint, ServiceClient};

use tacacsrs_networking::session::Session;

use crate::commands::accounting::send_accounting_request;

use super::super::progress::{ProgressConfig, ProgressTracker};
use super::super::types::{AccountingRequest, BatchRequest, LoadTestResult};

pub(super) async fn service_client(endpoint: &str) -> anyhow::Result<ServiceClient> {
    let endpoint = IpcEndpoint::from_str(endpoint).context("Invalid service endpoint")?;
    ServiceClient::connect(endpoint)
        .await
        .context("Failed to connect to TACACS+ service")
}

pub(super) fn to_service_accounting_request(request: &AccountingRequest) -> AccountingOperation {
    AccountingOperation {
        user: request.user.clone(),
        port: request.port.clone(),
        remote_address: request.rem_addr.clone(),
        command: request.cmd.clone(),
        command_arguments: request.cmd_args.clone(),
    }
}

pub(super) fn validate_service_mode_request(request: &BatchRequest) -> Result<(), String> {
    match request {
        BatchRequest::Accounting(req) if req.session_id.is_some() => {
            Err("Central TACACS+ service mode does not support client-specified session IDs"
                .to_owned())
        }
        _ => Ok(()),
    }
}

/// Executes a single batch request on a session
pub(super) async fn execute_single_request(
    session: Session,
    request: &BatchRequest,
) -> Result<String, String> {
    match request {
        BatchRequest::Accounting(req) => {
            let cmd_args = if req.cmd_args.is_empty() {
                None
            } else {
                Some(&req.cmd_args)
            };

            match send_accounting_request(
                session,
                &req.user,
                &req.port,
                &req.rem_addr,
                &req.cmd,
                cmd_args,
            )
            .await
            {
                Ok(response) => Ok(format!("Accounting success: {response:?}")),
                Err(error) => Err(format!("Accounting failed: {error}")),
            }
        }
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

pub(super) fn load_test_iterations(
    requests: &[BatchRequest],
    repetitions: usize,
) -> impl Iterator<Item = (usize, usize, &BatchRequest)> {
    (0..repetitions).flat_map(move |rep| {
        requests
            .iter()
            .enumerate()
            .map(move |(idx, req)| (rep, idx, req))
    })
}

/// Executes load test iterations with controlled concurrency.
pub(super) async fn run_load_test<'a, I, F, Fut>(
    total_requests: usize,
    iterations: I,
    max_parallel: usize,
    send_request: F,
) -> LoadTestResult
where
    I: Iterator<Item = (usize, usize, &'a BatchRequest)> + Send,
    F: Fn(usize, usize, &'a BatchRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), String>> + Send,
{
    let start_time = Instant::now();
    let tracker = ProgressTracker::new(ProgressConfig {
        total_requests,
        ..Default::default()
    });

    let results = stream::iter(iterations)
        .map(|(rep, idx, request)| {
            let completed = tracker.completed.clone();
            let failed = tracker.failed.clone();
            let first_failure = tracker.first_failure.clone();
            let execution = send_request(rep, idx, request);

            async move {
                if failed.load(Ordering::Relaxed) {
                    return false;
                }

                match execution.await {
                    Ok(()) => {
                        completed.fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Err(error) => {
                        if !failed.swap(true, Ordering::Relaxed) {
                            let mut failure = first_failure.lock().await;
                            *failure = Some(error);
                        }
                        false
                    }
                }
            }
        })
        .buffer_unordered(max_parallel)
        .collect::<Vec<_>>()
        .await;

    let failure_msg = tracker.finish().await;
    build_load_test_result(start_time, total_requests, &results, failure_msg)
}

/// Builds the final load test result from execution data
fn build_load_test_result(
    start_time: Instant,
    total_requests: usize,
    results: &[bool],
    failure_msg: Option<String>,
) -> LoadTestResult {
    let duration = start_time.elapsed();
    let successful_requests = results.iter().filter(|&&result| result).count();
    let failed_requests = usize::from(failure_msg.is_some());
    #[allow(clippy::cast_precision_loss)]
    let requests_per_second = if duration.as_secs_f64() > 0.0 {
        successful_requests as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    LoadTestResult {
        total_requests,
        successful_requests,
        failed_requests,
        duration,
        first_failure: failure_msg,
        requests_per_second,
    }
}
