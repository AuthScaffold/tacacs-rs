use futures::stream::{self, StreamExt};
use std::future::Future;
#[cfg(target_os = "linux")]
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::Instant;
#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use tacacsrs_agent_client::{IpcEndpoint, ServiceClient};
#[cfg(target_os = "linux")]
use tacacsrs_protocol::operations::{AccountingOperation};
use tacacsrs_protocol::exchange::authorization::AuthorizationExchange;
use tacacsrs_protocol::operations::{
    AuthorizationAuthenticationContext as ProtocolAuthenticationContext, AuthorizationOperation,
};

use crate::commands::accounting::send_accounting_request;
use crate::connection::Connection;

use super::super::progress::{ProgressConfig, ProgressTracker};
#[cfg(target_os = "linux")]
use super::super::types::AccountingRequest;
use super::super::types::{
    AuthorizationAuthenticationContext, AuthorizationRequest, BatchRequest, LoadTestResult,
};

#[cfg(target_os = "linux")]
pub(super) async fn service_client(endpoint: &str) -> anyhow::Result<ServiceClient> {
    let endpoint = IpcEndpoint::from_str(endpoint).context("Invalid service endpoint")?;
    ServiceClient::connect(endpoint)
        .await
        .context("Failed to connect to TACACS+ service")
}

#[cfg(target_os = "linux")]
pub(super) fn to_service_accounting_request(request: &AccountingRequest) -> AccountingOperation {
    crate::commands::accounting::accounting_operation(
        &request.user,
        &request.port,
        &request.rem_addr,
        &request.cmd,
        Some(&request.cmd_args),
    )
}

pub(super) fn direct_authorization_exchange(
    request: &AuthorizationRequest,
) -> anyhow::Result<AuthorizationExchange> {
    authorization_operation(request)?.exchange()
}

pub(super) fn authorization_operation(
    request: &AuthorizationRequest,
) -> anyhow::Result<AuthorizationOperation> {
    let context = match request.authentication_context {
        AuthorizationAuthenticationContext::Ascii => ProtocolAuthenticationContext::TacacsAscii,
        AuthorizationAuthenticationContext::Pap => ProtocolAuthenticationContext::TacacsPap,
        AuthorizationAuthenticationContext::Unauthenticated => {
            ProtocolAuthenticationContext::Unauthenticated
        }
    };
    let mut builder = AuthorizationOperation::builder(
        request.user.clone(),
        u32::from(request.privilege_level),
        context,
    )
    .port(request.port.clone())
    .remote_address(request.rem_addr.clone())
    .service("shell");
    builder = match &request.cmd {
        Some(command) => builder
            .command(command)
            .command_args(request.cmd_args.clone()),
        None => builder.command(""),
    };
    builder.build()
}

/// Runs a single batch request over a connection.
pub(super) async fn execute_single_request(
    connection: &Connection,
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
                connection,
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
            Err(format!(
                "PAP authentication is not supported in batch files. Use the authentication command with a prompt or --password-stdin (user: {})",
                req.user
            ))
        }
        BatchRequest::Authorization(req) => connection
            .execute(direct_authorization_exchange(req).map_err(|error| error.to_string())?)
            .await
            .map(|response| format!("Authorization success: {response:?}"))
            .map_err(|error| format!("Authorization failed: {error}")),
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

/// Runs load test iterations with controlled concurrency.
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

/// Builds the final load test result from run data.
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
