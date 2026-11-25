//! Shared operation concurrency and admission failure types.

use std::time::Duration;

use tacacsrs_networking::admission::{
    AdmissionError as PoolError, AdmissionPool, AdmissionReservation, RateLimiter,
};
use tacacsrs_networking::RequestDeadline;
use tacacsrs_protocol::failure::{DeliveryState, FailureCategory, FailureFacts, FailurePhase};
use tacacsrs_protocol::failure::ServiceError;
pub(crate) use tacacsrs_networking::admission::AdmissionPermit;

use crate::config::RuntimePolicy;

use super::OperationKind;

/// Shared operation concurrency and packet rate capacity retained across routing generations.
pub(crate) struct AdmissionRegistry {
    operations: [AdmissionPool; 3],
    operation_rates: [RateLimiter; 3],
    upstream_rate: RateLimiter,
}

fn map_wait_error(error: PoolError, wait_timeout: Duration) -> AdmissionError {
    match error {
        PoolError::Full => AdmissionError::Full,
        PoolError::Closed => AdmissionError::Closed,
        PoolError::Expired => AdmissionError::CapacityTimeout { wait_timeout },
    }
}

impl AdmissionRegistry {
    pub(crate) fn close(&self) {
        for operation in &self.operations {
            operation.close();
        }
        for limiter in &self.operation_rates {
            limiter.close();
        }
        self.upstream_rate.close();
    }

    pub(crate) fn new(policy: &RuntimePolicy) -> Self {
        let operations = OperationKind::ALL.map(|operation| {
            let limits = policy.limits(operation);
            AdmissionPool::new(limits.max_concurrent_requests())
        });
        let operation_rates = OperationKind::ALL.map(|operation| {
            let limits = policy.limits(operation);
            RateLimiter::new(limits.max_packets_per_second())
        });
        let upstream_rate = RateLimiter::new(policy.max_upstream_packets_per_second());
        Self {
            operations,
            operation_rates,
            upstream_rate,
        }
    }

    pub(crate) fn update(&self, policy: &RuntimePolicy) {
        for operation in OperationKind::ALL {
            let limits = policy.limits(operation);
            self.operations[operation.index()].update(limits.max_concurrent_requests());
            self.operation_rates[operation.index()].update(limits.max_packets_per_second());
        }
        self.upstream_rate
            .update(policy.max_upstream_packets_per_second());
    }

    #[cfg(test)]
    pub(crate) async fn acquire(
        &self,
        operation: OperationKind,
        wait_timeout: Duration,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let deadline = RequestDeadline::after(wait_timeout)
            .map_err(|_| AdmissionError::CapacityTimeout { wait_timeout })?;
        self.acquire_until(operation, deadline, wait_timeout).await
    }

    #[cfg(test)]
    pub(crate) async fn acquire_until(
        &self,
        operation: OperationKind,
        deadline: RequestDeadline,
        wait_timeout: Duration,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let reservation = self.reserve(operation, deadline)?;
        self.admit_reserved(operation, reservation, deadline, wait_timeout)
            .await
    }

    pub(crate) async fn admit_reserved(
        &self,
        operation: OperationKind,
        reservation: AdmissionReservation,
        deadline: RequestDeadline,
        wait_timeout: Duration,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let wait_deadline = deadline.capped(wait_timeout);
        let permit = reservation
            .wait_until(wait_deadline)
            .await
            .map_err(|error| map_wait_error(error, wait_timeout))?;
        self.operation_rates[operation.index()]
            .acquire(wait_deadline)
            .await
            .map_err(|error| map_wait_error(error, wait_timeout))?;
        self.upstream_rate
            .acquire(wait_deadline)
            .await
            .map_err(|error| map_wait_error(error, wait_timeout))?;
        Ok(permit)
    }

    pub(crate) fn reserve(
        &self,
        operation: OperationKind,
        deadline: RequestDeadline,
    ) -> Result<AdmissionReservation, AdmissionError> {
        self.operations[operation.index()]
            .reserve(deadline)
            .map_err(|error| match error {
                PoolError::Full => AdmissionError::Full,
                PoolError::Closed => AdmissionError::Closed,
                PoolError::Expired => AdmissionError::CapacityTimeout {
                    wait_timeout: Duration::ZERO,
                },
            })
    }
}

/// Reason that a local request did not enter the upstream routing path.
#[derive(Debug)]
pub(crate) enum AdmissionError {
    Closed,
    BodyTooLarge { actual: usize, maximum: usize },
    CapacityTimeout { wait_timeout: Duration },
    Full,
    NoEligibleServer { operation: OperationKind },
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => formatter.write_str("The TACACS+ service is closed"),
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
    pub(crate) fn into_service_error(self) -> ServiceError {
        let category = match self {
            Self::Closed => FailureCategory::Cancelled,
            Self::BodyTooLarge { .. } => FailureCategory::InvalidRequest,
            Self::CapacityTimeout { .. } => FailureCategory::Deadline,
            Self::Full => FailureCategory::Overloaded,
            Self::NoEligibleServer { .. } => FailureCategory::Unavailable,
        };
        ServiceError::new(
            self.to_string(),
            FailureFacts::new(category, FailurePhase::Admission, DeliveryState::NotSent),
        )
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

    #[tokio::test(start_paused = true)]
    async fn authentication_flood_is_paced_without_starving_accounting() {
        let auth = RequestLimits::new(1024, 8)
            .unwrap()
            .with_max_packets_per_second(2)
            .unwrap();
        let accounting = RequestLimits::new(1024, 8)
            .unwrap()
            .with_max_packets_per_second(10)
            .unwrap();
        let policy = RuntimePolicy::new(
            FailoverStrategy::default(),
            FailoverStrategy::default(),
            OperationPolicies::new(auth, accounting, accounting),
            Duration::from_secs(30),
        )
        .unwrap()
        .with_max_upstream_packets_per_second(10)
        .unwrap();
        let registry = Arc::new(AdmissionRegistry::new(&policy));

        // Exhaust the 2-packet authentication burst immediately.
        drop(
            registry
                .acquire(OperationKind::Authentication, Duration::from_secs(5))
                .await
                .unwrap(),
        );
        drop(
            registry
                .acquire(OperationKind::Authentication, Duration::from_secs(5))
                .await
                .unwrap(),
        );

        // Queue several more authentication requests that must pace at 500 ms each.
        let mut auth_waiters = Vec::new();
        for _ in 0..4 {
            let registry = Arc::clone(&registry);
            auth_waiters.push(tokio::spawn(async move {
                let start = tokio::time::Instant::now();
                let _permit = registry
                    .acquire(OperationKind::Authentication, Duration::from_secs(5))
                    .await
                    .unwrap();
                start.elapsed()
            }));
        }
        tokio::task::yield_now().await;

        // Accounting still has 8 of the 10 aggregate burst tokens available immediately.
        let acct_start = tokio::time::Instant::now();
        for _ in 0..8 {
            drop(
                registry
                    .acquire(OperationKind::Accounting, Duration::from_secs(1))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            acct_start.elapsed(),
            Duration::ZERO,
            "throttled authentication waiters must not block accounting at the global limiter"
        );

        let mut elapsed = Vec::new();
        for waiter in auth_waiters {
            elapsed.push(waiter.await.unwrap());
        }
        assert_eq!(
            elapsed,
            vec![
                Duration::from_millis(500),
                Duration::from_millis(1000),
                Duration::from_millis(1500),
                Duration::from_millis(2000),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn aggregate_upstream_rate_caps_combined_multi_operation_bursts() {
        let per_op = RequestLimits::new(1024, 8)
            .unwrap()
            .with_max_packets_per_second(10)
            .unwrap();
        let policy = RuntimePolicy::new(
            FailoverStrategy::default(),
            FailoverStrategy::default(),
            OperationPolicies::new(per_op, per_op, per_op),
            Duration::from_secs(30),
        )
        .unwrap()
        .with_max_upstream_packets_per_second(4)
        .unwrap();
        let registry = AdmissionRegistry::new(&policy);

        let start = tokio::time::Instant::now();
        for operation in [
            OperationKind::Authentication,
            OperationKind::Authorization,
            OperationKind::Accounting,
            OperationKind::Accounting,
        ] {
            drop(
                registry
                    .acquire(operation, Duration::from_secs(5))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(start.elapsed(), Duration::ZERO);

        // A 5th request in any operation must wait 250 ms for the 4 pkt/s aggregate limiter.
        drop(
            registry
                .acquire(OperationKind::Authorization, Duration::from_secs(5))
                .await
                .unwrap(),
        );
        assert_eq!(start.elapsed(), Duration::from_millis(250));
    }
}
