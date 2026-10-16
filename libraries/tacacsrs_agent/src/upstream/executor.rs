//! The one retry loop that applies a [`FailoverPlan`].
//!
//! The client API bridge and the raw TACACS+ proxy bridge use different request
//! types, reply types, and error types. They use the same failover algorithm.
//! This module owns that algorithm. A caller supplies one
//! [`FailoverAttempt`] implementation and receives one [`FailoverOutcome`].
//!
//! A caller must not read [`FailoverPlan`] itself. If a caller needs a new
//! control-flow shape, add a variant here. This keeps strategy interpretation
//! out of the service modules.

use async_trait::async_trait;

use super::failover::{AttemptDisposition, FailoverPlan};

/// Result of one attempt against one selected server.
#[derive(Debug)]
pub(crate) enum Attempt<Value, Error> {
    /// The server returned a final result. No other server is tried.
    Accepted(Value),
    /// The server returned a valid reply that reports a server error.
    ///
    /// The plan decides whether the next eligible server receives the request.
    Rejected(Value),
    /// The attempt did not produce a reply. The plan decides whether the next
    /// eligible server receives the request.
    Failed {
        /// Error returned to the local client if no other attempt succeeds.
        error: Error,
        /// Replay safety class for this failure.
        disposition: AttemptDisposition,
    },
    /// The request cannot succeed on any server. No other server is tried.
    Aborted(Error),
}

/// Final result of one local request across all permitted attempts.
#[derive(Debug)]
pub(crate) enum FailoverOutcome<Value, Error> {
    /// One attempt returned a final result.
    Accepted(Value),
    /// The last permitted attempt returned a server error reply.
    Rejected(Value),
    /// Every permitted attempt failed without a reply.
    Failed(Error),
    /// One attempt stopped the request before the plan was exhausted.
    Aborted(Error),
    /// The plan permitted no attempt. This indicates a plan construction bug.
    NoAttempt,
}

/// One local request that the failover executor can retry on other servers.
#[async_trait]
pub(crate) trait FailoverAttempt: Send {
    /// Value that a successful or rejected attempt produces.
    type Value: Send;
    /// Error that a failed attempt produces.
    type Error: Send;

    /// Runs one attempt. `attempt_index` starts at zero and is for log messages.
    async fn attempt(&mut self, attempt_index: usize) -> Attempt<Self::Value, Self::Error>;

    /// Releases a value that the executor will not return.
    ///
    /// The executor calls this before it retries a [`Attempt::Rejected`] value.
    /// An implementation that holds an open upstream session must close it here.
    async fn discard(&mut self, value: Self::Value) {
        drop(value);
    }
}

/// Runs `attempt` until the plan stops permitting another server.
pub(crate) async fn run_with_failover<Runner>(
    plan: FailoverPlan,
    runner: &mut Runner,
) -> FailoverOutcome<Runner::Value, Runner::Error>
where
    Runner: FailoverAttempt + ?Sized,
{
    for attempt_index in 0..plan.max_attempts() {
        let completed_attempts = attempt_index + 1;
        match runner.attempt(attempt_index).await {
            Attempt::Accepted(value) => return FailoverOutcome::Accepted(value),
            Attempt::Aborted(error) => return FailoverOutcome::Aborted(error),
            Attempt::Rejected(value) => {
                if plan.retry_after(completed_attempts, AttemptDisposition::ServerError) {
                    runner.discard(value).await;
                    continue;
                }
                return FailoverOutcome::Rejected(value);
            }
            Attempt::Failed { error, disposition } => {
                if plan.retry_after(completed_attempts, disposition) {
                    continue;
                }
                return FailoverOutcome::Failed(error);
            }
        }
    }

    FailoverOutcome::NoAttempt
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::config::{FailoverStrategy, OperationPolicies, PolicyService, RuntimePolicy};
    use crate::upstream::OperationKind;

    use super::*;

    struct ScriptedRunner {
        scripted: Vec<Attempt<&'static str, &'static str>>,
        discarded: Vec<&'static str>,
        attempts: usize,
    }

    impl ScriptedRunner {
        fn new(scripted: Vec<Attempt<&'static str, &'static str>>) -> Self {
            Self {
                scripted,
                discarded: Vec::new(),
                attempts: 0,
            }
        }
    }

    #[async_trait]
    impl FailoverAttempt for ScriptedRunner {
        type Value = &'static str;
        type Error = &'static str;

        async fn attempt(&mut self, attempt_index: usize) -> Attempt<Self::Value, Self::Error> {
            self.attempts += 1;
            assert_eq!(attempt_index, self.attempts - 1);
            self.scripted.remove(0)
        }

        async fn discard(&mut self, value: Self::Value) {
            self.discarded.push(value);
        }
    }

    fn plan(strategy: FailoverStrategy, servers: usize) -> FailoverPlan {
        let policy = RuntimePolicy::new(
            strategy,
            strategy,
            OperationPolicies::default(),
            Duration::from_secs(30),
        )
        .expect("test policy");
        FailoverPlan::new(&policy, PolicyService::ClientApi, OperationKind::Authorization, servers)
    }

    #[tokio::test]
    async fn accepted_attempt_stops_immediately() {
        let mut runner = ScriptedRunner::new(vec![Attempt::Accepted("first")]);

        let outcome =
            run_with_failover(plan(FailoverStrategy::OrderedSafeRetry, 3), &mut runner).await;

        assert!(matches!(outcome, FailoverOutcome::Accepted("first")));
        assert_eq!(runner.attempts, 1);
    }

    #[tokio::test]
    async fn rejected_attempt_is_discarded_before_the_next_server() {
        let mut runner =
            ScriptedRunner::new(vec![Attempt::Rejected("first"), Attempt::Accepted("second")]);

        let outcome =
            run_with_failover(plan(FailoverStrategy::OrderedSafeRetry, 2), &mut runner).await;

        assert!(matches!(outcome, FailoverOutcome::Accepted("second")));
        assert_eq!(runner.discarded, vec!["first"]);
    }

    #[tokio::test]
    async fn the_last_rejected_value_is_returned_to_the_caller() {
        let mut runner = ScriptedRunner::new(vec![Attempt::Rejected("only")]);

        let outcome =
            run_with_failover(plan(FailoverStrategy::DeferredFailover, 3), &mut runner).await;

        assert!(matches!(outcome, FailoverOutcome::Rejected("only")));
        assert!(runner.discarded.is_empty());
    }

    #[tokio::test]
    async fn aborted_attempt_stops_without_another_server() {
        let mut runner = ScriptedRunner::new(vec![Attempt::Aborted("invalid")]);

        let outcome =
            run_with_failover(plan(FailoverStrategy::OrderedSafeRetry, 3), &mut runner).await;

        assert!(matches!(outcome, FailoverOutcome::Aborted("invalid")));
        assert_eq!(runner.attempts, 1);
    }

    #[tokio::test]
    async fn the_last_failure_is_returned_when_every_server_fails() {
        let mut runner = ScriptedRunner::new(vec![
            Attempt::Failed {
                error: "first",
                disposition: AttemptDisposition::NotSent,
            },
            Attempt::Failed {
                error: "second",
                disposition: AttemptDisposition::NotSent,
            },
        ]);

        let outcome =
            run_with_failover(plan(FailoverStrategy::OrderedSafeRetry, 2), &mut runner).await;

        assert!(matches!(outcome, FailoverOutcome::Failed("second")));
        assert_eq!(runner.attempts, 2);
    }
}
