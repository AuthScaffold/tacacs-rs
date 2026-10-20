use std::future::Future;
use std::num::NonZeroUsize;
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
/// The test repeats every request `repetitions` times and reuses one backend.
/// After the first failure, pending requests do not start. In-flight requests
/// finish, and their successes count toward the result.
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
        .map_err(|error| format!("{operation} failed: {error:#}"))
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
///
/// Drains in-flight requests before reading the completion count. The scheduler
/// retains no per-request results. Cancellation drops in-flight request futures.
pub(super) async fn run_load_test<'a, I, F, Fut>(
    total_requests: usize,
    iterations: I,
    max_parallel: NonZeroUsize,
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

    stream::iter(iterations)
        .map(|(rep, idx, request)| {
            let completed = tracker.completed.clone();
            let failed = tracker.failed.clone();
            let first_failure = tracker.first_failure.clone();
            let execution = send_request(rep, idx, request);

            async move {
                if failed.load(Ordering::Relaxed) {
                    return;
                }

                match execution.await {
                    Ok(()) => {
                        completed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        if !failed.swap(true, Ordering::Relaxed) {
                            let mut failure = first_failure.lock().await;
                            *failure = Some(error);
                        }
                    }
                }
            }
        })
        .buffer_unordered(max_parallel.get())
        .for_each(|()| async {})
        .await;

    let successful_requests = tracker.completed_count();
    let failure_msg = tracker.finish().await;
    build_load_test_result(start_time, total_requests, successful_requests, failure_msg)
}

/// Builds the final load test result from run data.
fn build_load_test_result(
    start_time: Instant,
    total_requests: usize,
    successful_requests: usize,
    failure_msg: Option<String>,
) -> LoadTestResult {
    let duration = start_time.elapsed();
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
    use std::future::pending;
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::sync::{Barrier, Notify, Semaphore};
    use tokio::time::timeout;

    use crate::batch::types::{AccountingRequest, BatchRequest};

    use super::{build_load_test_result, format_request_outcome, load_test_iterations, run_load_test};

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
    fn batch_failure_rendering_preserves_the_cause() {
        let error =
            anyhow::anyhow!("connection refused").context("Failed to send accounting request");
        let message = format_request_outcome("Accounting", Err::<(), _>(error)).unwrap_err();
        assert!(message.contains("Failed to send accounting request"));
        assert!(message.contains("connection refused"));
    }

    #[test]
    fn build_load_test_result_reports_success_without_failures() {
        let result = build_load_test_result(Instant::now(), 4, 4, None);
        assert!(result.is_success());
        assert_eq!(result.successful_requests, 4);
        assert_eq!(result.failed_requests, 0);
    }

    #[test]
    fn build_load_test_result_counts_a_single_failure() {
        let result = build_load_test_result(Instant::now(), 4, 2, Some("boom".to_owned()));
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
            NonZeroUsize::new(4).unwrap(),
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
        let started = AtomicUsize::new(0);
        let result =
            run_load_test(5, load_test_iterations(&requests, 5), NonZeroUsize::MIN, |rep, _, _| {
                let started = &started;
                async move {
                    started.fetch_add(1, Ordering::Relaxed);
                    if rep == 2 {
                        Err(format!("boom at rep {}", rep + 1))
                    } else {
                        Ok(())
                    }
                }
            })
            .await;
        assert!(!result.is_success());
        assert_eq!(result.total_requests, 5);
        assert_eq!(result.successful_requests, 2);
        assert_eq!(result.failed_requests, 1);
        assert_eq!(result.first_failure.as_deref(), Some("boom at rep 3"));
        assert_eq!(started.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn load_test_with_zero_requests_never_sends() {
        for (requests, repetitions) in [(Vec::new(), 3), (vec![accounting_request("a")], 0)] {
            let result = timeout(
                Duration::from_secs(5),
                run_load_test(
                    0,
                    load_test_iterations(&requests, repetitions),
                    NonZeroUsize::MIN,
                    |_, _, _| async {
                        panic!("A zero-request load test must not send a request");
                    },
                ),
            )
            .await
            .expect("The zero-request load test must finish");

            assert!(result.is_success());
            assert_eq!(result.total_requests, 0);
            assert_eq!(result.successful_requests, 0);
            assert_eq!(result.failed_requests, 0);
            assert_eq!(result.requests_per_second, 0.0);
        }
    }

    #[tokio::test]
    async fn load_test_bounds_concurrency_and_completes_every_request() {
        let requests = vec![accounting_request("a")];
        let started = AtomicUsize::new(0);
        let entered = Barrier::new(4);
        let release = Semaphore::new(0);
        let run = run_load_test(
            6,
            load_test_iterations(&requests, 6),
            NonZeroUsize::new(3).unwrap(),
            |_, _, _| async {
                started.fetch_add(1, Ordering::Relaxed);
                entered.wait().await;
                release.acquire().await.unwrap().forget();
                Ok(())
            },
        );
        let control = async {
            for expected in [3, 6] {
                entered.wait().await;
                assert_eq!(started.load(Ordering::Relaxed), expected);
                release.add_permits(3);
            }
        };
        let (result, ()) = timeout(Duration::from_secs(5), async { tokio::join!(run, control) })
            .await
            .expect("Both waves of load requests must finish");

        assert!(result.is_success());
        assert_eq!(result.total_requests, 6);
        assert_eq!(result.successful_requests, 6);
        assert_eq!(result.failed_requests, 0);
    }

    #[tokio::test]
    async fn load_test_keeps_the_first_of_concurrent_failures() {
        let requests = vec![accounting_request("a")];
        let started = AtomicUsize::new(0);
        let finished = AtomicUsize::new(0);
        let entered = Barrier::new(4);
        let first_failure = Notify::new();
        let later_failures = Semaphore::new(0);
        let run = run_load_test(
            9,
            load_test_iterations(&requests, 9),
            NonZeroUsize::new(3).unwrap(),
            |rep, _, _| {
                let started = &started;
                let finished = &finished;
                let entered = &entered;
                let first_failure = &first_failure;
                let later_failures = &later_failures;
                async move {
                    started.fetch_add(1, Ordering::Relaxed);
                    entered.wait().await;
                    if rep == 2 {
                        first_failure.notify_one();
                    } else {
                        later_failures.acquire().await.unwrap().forget();
                    }
                    finished.fetch_add(1, Ordering::Relaxed);
                    Err(format!("boom at rep {}", rep + 1))
                }
            },
        );
        let control = async {
            entered.wait().await;
            first_failure.notified().await;
            later_failures.add_permits(2);
        };
        let (result, ()) = timeout(Duration::from_secs(5), async { tokio::join!(run, control) })
            .await
            .expect("All in-flight failures must finish");

        assert!(!result.is_success());
        assert_eq!(result.total_requests, 9);
        assert_eq!(result.successful_requests, 0);
        assert_eq!(result.failed_requests, 1);
        assert_eq!(result.first_failure.as_deref(), Some("boom at rep 3"));
        assert_eq!(started.load(Ordering::Relaxed), 3);
        assert_eq!(finished.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn load_test_counts_in_flight_successes_after_a_failure() {
        let requests = vec![accounting_request("a")];
        let started = AtomicUsize::new(0);
        let entered = Barrier::new(4);
        let first_failure = Notify::new();
        let later_successes = Semaphore::new(0);
        let run = run_load_test(
            9,
            load_test_iterations(&requests, 9),
            NonZeroUsize::new(3).unwrap(),
            |rep, _, _| {
                let started = &started;
                let entered = &entered;
                let first_failure = &first_failure;
                let later_successes = &later_successes;
                async move {
                    started.fetch_add(1, Ordering::Relaxed);
                    entered.wait().await;
                    if rep == 1 {
                        first_failure.notify_one();
                        Err("boom".to_owned())
                    } else {
                        later_successes.acquire().await.unwrap().forget();
                        Ok(())
                    }
                }
            },
        );
        let control = async {
            entered.wait().await;
            first_failure.notified().await;
            later_successes.add_permits(2);
        };
        let (result, ()) = timeout(Duration::from_secs(5), async { tokio::join!(run, control) })
            .await
            .expect("Successful in-flight requests must finish after a failure");

        assert!(!result.is_success());
        assert_eq!(result.total_requests, 9);
        assert_eq!(result.successful_requests, 2);
        assert_eq!(result.failed_requests, 1);
        assert_eq!(result.first_failure.as_deref(), Some("boom"));
        assert_eq!(started.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn load_test_cancellation_drops_in_flight_requests() {
        let requests = vec![accounting_request("a")];
        let started = AtomicUsize::new(0);
        let entered = Barrier::new(4);
        let in_flight = Arc::new(());
        let mut run = Box::pin(run_load_test(
            9,
            load_test_iterations(&requests, 9),
            NonZeroUsize::new(3).unwrap(),
            |_, _, _| {
                let in_flight = Arc::clone(&in_flight);
                let started = &started;
                let entered = &entered;
                async move {
                    let _in_flight = in_flight;
                    started.fetch_add(1, Ordering::Relaxed);
                    entered.wait().await;
                    pending::<Result<(), String>>().await
                }
            },
        ));

        timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut run => panic!("Pending load requests must not finish: {result:?}"),
                _ = entered.wait() => {}
            }
        })
        .await
        .expect("All in-flight requests must start before cancellation");
        assert_eq!(started.load(Ordering::Relaxed), 3);
        assert_eq!(Arc::strong_count(&in_flight), 4);

        drop(run);

        assert_eq!(Arc::strong_count(&in_flight), 1);
        assert_eq!(started.load(Ordering::Relaxed), 3);
    }
}
