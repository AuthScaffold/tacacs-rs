use std::future::Future;
use std::sync::atomic::Ordering;
use std::time::Instant;

use futures::future::join_all;
use futures::stream::{self, StreamExt};

use tacacsrs_protocol::operations::{
    AuthorizationAuthenticationContext as ProtocolAuthenticationContext, AuthorizationOperation,
};

use crate::backend::Backend;
use crate::commands::accounting::accounting_operation;

use super::super::progress::{print_load_test_summary, ProgressConfig, ProgressTracker};
use super::super::types::{
    AuthorizationAuthenticationContext, AuthorizationRequest, BatchFile, BatchRequest,
    LoadTestConfig, LoadTestResult, RequestResult,
};

/// Builds an [`AuthorizationOperation`] from a batch authorization request.
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

/// Runs one batch request against the resolved backend and formats its outcome.
///
/// This is the single per-request dispatcher shared by direct and IPC batch
/// execution. PAP authentication requests are rejected before any backend call.
pub(super) async fn execute_batch_request(
    backend: &Backend,
    request: &BatchRequest,
) -> Result<String, String> {
    match request {
        BatchRequest::Accounting(req) => {
            let operation = accounting_operation(
                &req.user,
                &req.port,
                &req.rem_addr,
                &req.cmd,
                Some(&req.cmd_args),
            );
            format_request_outcome("Accounting", backend.accounting(&operation).await)
        }
        BatchRequest::Authentication(req) => Err(pap_batch_unsupported(&req.user)),
        BatchRequest::Authorization(req) => {
            let operation = authorization_operation(req).map_err(|error| error.to_string())?;
            format_request_outcome("Authorization", backend.authorization(&operation).await)
        }
    }
}

/// Logs and prints the batch description, if the file provides one.
pub(super) fn announce_batch(batch: &BatchFile) {
    if let Some(description) = &batch.metadata.description {
        log::info!("Running batch: {description}");
        println!("Batch: {description}");
    }
}

/// Runs every request against the backend, sequentially or in parallel.
///
/// Parallel runs clone the backend per request. A cloned [`Backend`] shares the
/// same direct connection or persistent IPC channel, so no new transport opens.
pub(super) async fn run_requests(
    backend: &Backend,
    requests: &[BatchRequest],
    parallel: bool,
) -> Vec<RequestResult> {
    if parallel {
        let futures = requests.iter().enumerate().map(|(index, request)| {
            let backend = backend.clone();
            async move {
                RequestResult {
                    index,
                    request_type: request.type_name(),
                    result: execute_batch_request(&backend, request).await,
                }
            }
        });
        join_all(futures).await
    } else {
        let mut results = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            log::info!("Running request {}/{}", index + 1, requests.len());
            results.push(RequestResult {
                index,
                request_type: request.type_name(),
                result: execute_batch_request(backend, request).await,
            });
        }
        results
    }
}

/// Runs a load test against the backend with controlled concurrency.
///
/// The test repeats every request `repetitions` times and stops after the first
/// failure. It reuses one backend for the whole run.
pub(super) async fn run_batch_load_test(
    backend: &Backend,
    requests: &[BatchRequest],
    config: &LoadTestConfig,
) -> LoadTestResult {
    run_load_test(
        requests.len() * config.repetitions,
        load_test_iterations(requests, config.repetitions),
        config.max_parallel,
        move |rep, idx, request| {
            let backend = backend.clone();
            async move {
                execute_batch_request(&backend, request)
                    .await
                    .map(|_| ())
                    .map_err(|error| {
                        format!(
                            "Request failed at rep {}, request {} ({}): {}",
                            rep + 1,
                            idx + 1,
                            request.type_name(),
                            error
                        )
                    })
            }
        },
    )
    .await
}

/// Prints the load test summary and maps the result to the batch return value.
///
/// # Errors
///
/// Returns an error when the load test recorded a failure.
pub(super) fn finish_load_test(result: LoadTestResult) -> anyhow::Result<Vec<RequestResult>> {
    print_load_test_summary(&result);

    if result.is_success() {
        Ok(vec![])
    } else {
        anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default())
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
    use tacacsrs_ipc::proto;
    use tacacsrs_protocol::accounting::reply::AccountingReply;
    use tacacsrs_protocol::authentication::reply::AuthenticationReply;
    use tacacsrs_protocol::authorization::reply::AuthorizationReply;
    use tacacsrs_protocol::enumerations::{
        TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
        TacacsAuthorizationStatus,
    };
    use tacacsrs_protocol::failure::{
        DeliveryState, FailureCategory, FailureFacts, FailurePhase, ServiceError,
    };
    use tacacsrs_protocol::operations::{
        AccountingOperationResponse, AuthorizationOperationResponse,
        PapAuthenticationOperationResponse,
    };

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
            let remote = AccountingOperationResponse::try_from(proto::AccountingResponse::from(
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
                proto::AuthorizationResponse::from(direct.clone()),
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
            let remote = ServiceError::try_from(proto::ServiceError::from(direct.clone()))?;
            assert_eq!(direct, remote);
            assert_eq!(
                format_request_outcome("Accounting", Err::<(), _>(direct)),
                format_request_outcome("Accounting", Err::<(), _>(remote)),
            );
        }
        Ok(())
    }

    #[test]
    fn direct_and_ipc_pap_results_conform() -> anyhow::Result<()> {
        for status in [
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            TacacsAuthenticationStatus::TacPlusAuthenStatusFail,
            TacacsAuthenticationStatus::TacPlusAuthenStatusError,
        ] {
            let direct = PapAuthenticationOperationResponse::from_reply(
                "primary",
                AuthenticationReply {
                    status,
                    flags: TacacsAuthenticationReplyFlags::empty(),
                    server_msg: "status message".to_owned(),
                    data: vec![0, 255],
                },
            )?;
            let remote = PapAuthenticationOperationResponse::try_from(
                proto::PapAuthenticationResponse::from(direct.clone()),
            )?;
            assert_eq!(direct, remote);
        }
        Ok(())
    }

    #[test]
    fn batch_pap_rejection_never_contains_a_password() {
        assert_eq!(pap_batch_unsupported("alice"),
            "PAP authentication is not supported in batch files. Use the authentication command with a prompt or --password-stdin (user: alice)");
    }
}

#[cfg(test)]
mod load_test_tests {
    use std::time::Instant;

    use crate::batch::types::{AccountingRequest, BatchRequest};

    use super::{build_load_test_result, load_test_iterations, run_load_test};

    fn accounting_request(cmd: &str) -> BatchRequest {
        BatchRequest::Accounting(AccountingRequest {
            user: "alice".to_owned(),
            port: "tty0".to_owned(),
            rem_addr: "192.0.2.1".to_owned(),
            cmd: cmd.to_owned(),
            cmd_args: Vec::new(),
        })
    }

    #[test]
    fn load_test_iterations_expand_requests_by_repetition() {
        let requests = vec![accounting_request("a"), accounting_request("b")];
        let expanded: Vec<_> = load_test_iterations(&requests, 3)
            .map(|(rep, idx, _)| (rep, idx))
            .collect();
        assert_eq!(expanded, vec![(0, 0), (0, 1), (1, 0), (1, 1), (2, 0), (2, 1)]);
    }

    #[test]
    fn build_load_test_result_reports_success_without_failures() {
        let result = build_load_test_result(Instant::now(), 4, &[true, true, true, true], None);
        assert!(result.is_success());
        assert_eq!(result.successful_requests, 4);
        assert_eq!(result.failed_requests, 0);
    }

    #[test]
    fn build_load_test_result_counts_a_single_failure() {
        let result = build_load_test_result(
            Instant::now(),
            4,
            &[true, false, true],
            Some("boom".to_owned()),
        );
        assert!(!result.is_success());
        assert_eq!(result.successful_requests, 2);
        assert_eq!(result.failed_requests, 1);
        assert_eq!(result.first_failure.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn load_test_reports_success_when_all_requests_pass() {
        let requests = vec![accounting_request("a"), accounting_request("b")];
        let result = run_load_test(
            requests.len() * 2,
            load_test_iterations(&requests, 2),
            4,
            |_, _, _| async { Ok::<(), String>(()) },
        )
        .await;
        assert!(result.is_success());
        assert_eq!(result.successful_requests, 4);
        assert_eq!(result.failed_requests, 0);
        assert_eq!(result.total_requests, 4);
    }

    #[tokio::test]
    async fn load_test_stops_after_first_failure() {
        let requests = vec![accounting_request("a")];
        let result =
            run_load_test(5, load_test_iterations(&requests, 5), 1, |rep, _, _| async move {
                if rep == 2 {
                    Err(format!("boom at rep {}", rep + 1))
                } else {
                    Ok(())
                }
            })
            .await;
        assert!(!result.is_success());
        assert_eq!(result.failed_requests, 1);
        assert_eq!(result.first_failure.as_deref(), Some("boom at rep 3"));
    }
}
