use futures::stream::{self, StreamExt};
use std::future::Future;
#[cfg(target_os = "linux")]
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::Instant;
#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
#[cfg(target_os = "linux")]
use tacacsrs_protocol::operations::{AccountingOperation};
use tacacsrs_protocol::exchange::authorization::AuthorizationExchange;
use tacacsrs_protocol::operations::{
    AuthorizationAuthenticationContext as ProtocolAuthenticationContext, AuthorizationOperation,
    AuthorizationOperationResponse,
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
            let result = send_accounting_request(
                connection,
                &req.user,
                &req.port,
                &req.rem_addr,
                &req.cmd,
                Some(&req.cmd_args),
            )
            .await;
            format_request_outcome("Accounting", result)
        }
        BatchRequest::Authentication(req) => Err(pap_batch_unsupported(&req.user)),
        BatchRequest::Authorization(req) => {
            let result = connection
                .execute(direct_authorization_exchange(req).map_err(|error| error.to_string())?)
                .await
                .and_then(|reply| {
                    AuthorizationOperationResponse::from_reply(connection.server_name(), reply)
                });
            format_request_outcome("Authorization", result)
        }
    }
}

pub(super) fn pap_batch_unsupported(user: &str) -> String {
    format!(
        "PAP authentication is not supported in batch files. Use the authentication command with a prompt or --password-stdin (user: {user})"
    )
}

pub(super) fn format_request_outcome<Response: std::fmt::Debug, Error: std::fmt::Display>(
    operation: &str,
    result: Result<Response, Error>,
) -> Result<String, String> {
    result
        .map(|response| format!("{operation} response: {response:?}"))
        .map_err(|error| format!("{operation} failed: {error}"))
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use tacacsrs_ipc::ipc;
    use tacacsrs_protocol::accounting::reply::AccountingReply;
    use tacacsrs_protocol::authorization::reply::AuthorizationReply;
    use tacacsrs_protocol::enumerations::{TacacsAccountingStatus, TacacsAuthorizationStatus};
    use tacacsrs_protocol::failure::{DeliveryState, FailureCategory, FailureFacts, FailurePhase};
    use tacacsrs_protocol::operations::{AccountingOperationResponse, ServiceError};

    use super::*;

    #[test]
    fn direct_and_ipc_accounting_results_conform() -> anyhow::Result<()> {
        for status in [
            TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            TacacsAccountingStatus::TacPlusAcctStatusError,
            TacacsAccountingStatus::TacPlusAcctStatusFollow,
        ] {
            let direct = AccountingOperationResponse::from_reply(
                "primary",
                AccountingReply {
                    status,
                    server_msg: "status message".to_owned(),
                    data: "data".to_owned(),
                },
            );
            let remote = AccountingOperationResponse::try_from(ipc::AccountingResponse::from(
                direct.clone(),
            ))?;
            assert_eq!(direct, remote);
            assert_eq!(
                format_request_outcome("Accounting", Ok::<_, ServiceError>(direct)),
                format_request_outcome("Accounting", Ok::<_, ServiceError>(remote)),
            );
        }
        Ok(())
    }

    #[test]
    fn direct_and_ipc_authorization_results_conform() -> anyhow::Result<()> {
        for status in [
            TacacsAuthorizationStatus::TacPlusPassAdd,
            TacacsAuthorizationStatus::TacPlusPassRepl,
            TacacsAuthorizationStatus::TacPlusFail,
            TacacsAuthorizationStatus::TacPlusError,
            TacacsAuthorizationStatus::TacPlusFollow,
        ] {
            let direct = AuthorizationOperationResponse::from_reply(
                "primary",
                AuthorizationReply {
                    status,
                    server_msg: "status message".to_owned(),
                    data: "data".to_owned(),
                    args: vec!["cmd=show".to_owned(), "protocol*ssh".to_owned()],
                },
            )?;
            let remote = AuthorizationOperationResponse::try_from(
                ipc::AuthorizationResponse::from(direct.clone()),
            )?;
            assert_eq!(direct, remote);
            assert_eq!(
                format_request_outcome("Authorization", Ok::<_, ServiceError>(direct)),
                format_request_outcome("Authorization", Ok::<_, ServiceError>(remote)),
            );
        }
        Ok(())
    }

    #[test]
    fn structured_failures_survive_ipc_until_batch_rendering() -> anyhow::Result<()> {
        for (category, phase, delivery) in [
            (FailureCategory::InvalidRequest, FailurePhase::Validation, DeliveryState::NotSent),
            (FailureCategory::Unavailable, FailurePhase::Routing, DeliveryState::NotSent),
            (FailureCategory::Transport, FailurePhase::Upstream, DeliveryState::OutcomeUnknown),
        ] {
            let direct =
                ServiceError::new("operation failed", FailureFacts::new(category, phase, delivery))
                    .with_server("primary")
                    .with_runtime_generation(7);
            let remote = ServiceError::try_from(ipc::ServiceError::from(direct.clone()))?;
            assert_eq!(direct, remote);
            assert_eq!(
                format_request_outcome("Accounting", Err::<(), _>(direct)),
                format_request_outcome("Accounting", Err::<(), _>(remote)),
            );
        }
        Ok(())
    }

    #[test]
    fn batch_pap_rejection_never_contains_a_password() {
        assert_eq!(pap_batch_unsupported("alice"),
            "PAP authentication is not supported in batch files. Use the authentication command with a prompt or --password-stdin (user: alice)");
    }
}
