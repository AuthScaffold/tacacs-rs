//! Shared operation concurrency and admission failure types.

use std::time::Duration;

use tacacsrs_networking::admission::{AdmissionPool, AdmissionError as PoolError};
use tacacsrs_networking::RequestDeadline;
pub(crate) use tacacsrs_networking::admission::AdmissionPermit;

use crate::config::RuntimePolicy;

use super::OperationKind;

/// Shared operation capacity retained across routing generations.
pub(crate) struct AdmissionRegistry {
    operations: [AdmissionPool; 3],
}

impl AdmissionRegistry {
    pub(crate) fn new(policy: &RuntimePolicy) -> Self {
        let operations = OperationKind::ALL.map(|operation| {
            let limits = policy.limits(operation);
            AdmissionPool::new(limits.max_concurrent_requests())
        });
        Self { operations }
    }

    pub(crate) fn update(&self, policy: &RuntimePolicy) {
        for operation in OperationKind::ALL {
            let limits = policy.limits(operation);
            self.operations[operation.index()].update(limits.max_concurrent_requests());
        }
    }

    pub(crate) async fn acquire(
        &self,
        operation: OperationKind,
        wait_timeout: Duration,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let deadline = RequestDeadline::after(wait_timeout)
            .map_err(|_| AdmissionError::CapacityTimeout { wait_timeout })?;
        self.operations[operation.index()]
            .acquire(deadline)
            .await
            .map_err(|error| match error {
                PoolError::Full => AdmissionError::Full,
                PoolError::Expired => AdmissionError::CapacityTimeout { wait_timeout },
            })
    }
}

/// Reason that a local request did not enter the upstream routing path.
#[derive(Debug)]
pub(crate) enum AdmissionError {
    BodyTooLarge { actual: usize, maximum: usize },
    CapacityTimeout { wait_timeout: Duration },
    Full,
    NoEligibleServer { operation: OperationKind },
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyTooLarge { actual, maximum } => write!(
                formatter,
                "TACACS+ request body length {actual} exceeds the configured maximum of {maximum}"
            ),
            Self::CapacityTimeout { wait_timeout } => {
                write!(formatter, "No request capacity became available within {wait_timeout:?}")
            }
            Self::Full => formatter.write_str("The TACACS+ request admission queue is full"),
            Self::NoEligibleServer { operation } => write!(
                formatter,
                "No configured TACACS+ server supports {}; waiting for initial configuration",
                operation.name()
            ),
        }
    }
}

impl std::error::Error for AdmissionError {}

impl AdmissionError {
    #[must_use]
    pub(crate) const fn is_retriable(&self) -> bool {
        !matches!(self, Self::BodyTooLarge { .. })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use crate::config::{FailoverStrategy, OperationPolicies, RequestLimits};

    use super::*;

    fn policy_with_authentication_limit(
        max_body_length: usize,
        max_concurrent_requests: usize,
    ) -> RuntimePolicy {
        let authentication =
            RequestLimits::new(max_body_length, max_concurrent_requests).expect("test limits");
        RuntimePolicy::new(
            FailoverStrategy::default(),
            FailoverStrategy::default(),
            OperationPolicies::new(
                authentication,
                RequestLimits::new(1024, 8).expect("authorization limits"),
                RequestLimits::new(1024, 8).expect("accounting limits"),
            ),
            Duration::from_secs(30),
        )
        .expect("test policy")
    }

    #[tokio::test(start_paused = true)]
    async fn operation_limits_are_independent() {
        let registry = AdmissionRegistry::new(&RuntimePolicy::default());
        let authentication = registry
            .acquire(OperationKind::Authentication, Duration::from_secs(1))
            .await
            .expect("authentication capacity");
        let authorization = registry
            .acquire(OperationKind::Authorization, Duration::from_secs(1))
            .await
            .expect("authorization capacity");

        drop((authentication, authorization));
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_wait_stops_at_the_selected_server_timeout() {
        let one_request = RequestLimits::new(1024, 1).expect("test limits");
        let operations = OperationPolicies::new(one_request, one_request, one_request);
        let policy = RuntimePolicy::new(
            FailoverStrategy::DeferredFailover,
            FailoverStrategy::DeferredFailover,
            operations,
            Duration::from_secs(30),
        )
        .expect("test policy");
        let registry = Arc::new(AdmissionRegistry::new(&policy));
        let active = registry
            .acquire(OperationKind::Authentication, Duration::from_secs(5))
            .await
            .expect("first request capacity");
        let waiting = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                registry
                    .acquire(OperationKind::Authentication, Duration::from_secs(5))
                    .await
            })
        };
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;

        assert!(matches!(
            waiting.await.expect("waiting request joins"),
            Err(AdmissionError::CapacityTimeout { .. })
        ));
        drop(active);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_admission_is_bounded_by_operation_capacity() {
        let registry = AdmissionRegistry::new(&policy_with_authentication_limit(1024, 1));
        let _active = registry
            .acquire(OperationKind::Authentication, Duration::from_secs(5))
            .await
            .unwrap();
        let waiting = registry.acquire(OperationKind::Authentication, Duration::from_secs(5));
        tokio::pin!(waiting);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(waiting.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let excess = registry.acquire(OperationKind::Authentication, Duration::from_secs(5));
        tokio::pin!(excess);
        std::future::poll_fn(|context| {
            assert!(
                matches!(
                    std::future::Future::poll(excess.as_mut(), context),
                    std::task::Poll::Ready(Err(_))
                ),
                "excess requests must fail instead of adding an unbounded waiter"
            );
            std::task::Poll::Ready(())
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn live_limit_decrease_preserves_global_in_flight_accounting() {
        let registry = Arc::new(AdmissionRegistry::new(&policy_with_authentication_limit(1024, 2)));
        let first = registry
            .acquire(OperationKind::Authentication, Duration::from_secs(1))
            .await
            .expect("first permit");
        let second = registry
            .acquire(OperationKind::Authentication, Duration::from_secs(1))
            .await
            .expect("second permit");

        registry.update(&policy_with_authentication_limit(512, 1));
        drop(first);
        assert!(matches!(
            registry
                .acquire(OperationKind::Authentication, Duration::from_millis(1),)
                .await,
            Err(AdmissionError::CapacityTimeout { .. })
        ));

        drop(second);
        registry
            .acquire(OperationKind::Authentication, Duration::from_secs(1))
            .await
            .expect("new limit permits one request");
    }
}
