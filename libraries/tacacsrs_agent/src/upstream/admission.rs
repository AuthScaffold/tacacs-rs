//! Request-size and concurrency admission controls.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::RuntimePolicy;

use super::OperationKind;

struct OperationAdmission {
    max_body_length: AtomicUsize,
    concurrency_limit: AtomicUsize,
    permit_debt: AtomicUsize,
    semaphore: Arc<Semaphore>,
}

impl OperationAdmission {
    fn new(max_body_length: usize, max_concurrent_requests: usize) -> Self {
        Self {
            max_body_length: AtomicUsize::new(max_body_length),
            concurrency_limit: AtomicUsize::new(max_concurrent_requests),
            permit_debt: AtomicUsize::new(0),
            semaphore: Arc::new(Semaphore::new(max_concurrent_requests)),
        }
    }

    fn update(&self, max_body_length: usize, max_concurrent_requests: usize) {
        self.max_body_length
            .store(max_body_length, Ordering::Release);
        let previous = self
            .concurrency_limit
            .swap(max_concurrent_requests, Ordering::AcqRel);
        if max_concurrent_requests > previous {
            let increase = max_concurrent_requests - previous;
            let cancelled_debt = self.consume_debt(increase);
            self.semaphore.add_permits(increase - cancelled_debt);
        } else if max_concurrent_requests < previous {
            let reduction = previous - max_concurrent_requests;
            let removed = self.semaphore.forget_permits(reduction);
            self.permit_debt
                .fetch_add(reduction - removed, Ordering::AcqRel);
        }
    }

    fn consume_debt(&self, maximum: usize) -> usize {
        let mut current = self.permit_debt.load(Ordering::Acquire);
        loop {
            let consumed = current.min(maximum);
            match self.permit_debt.compare_exchange_weak(
                current,
                current - consumed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return consumed,
                Err(actual) => current = actual,
            }
        }
    }
}

/// Permit for one request in the shared operation limit.
pub(crate) struct AdmissionPermit {
    admission: Arc<OperationAdmission>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let permit = self.permit.take().expect("admission permit must exist");
        if self.admission.consume_debt(1) == 1 {
            permit.forget();
        }
    }
}

/// Immutable admission generation built from one runtime policy.
pub(crate) struct AdmissionRegistry {
    operations: [Arc<OperationAdmission>; 3],
}

impl AdmissionRegistry {
    pub(crate) fn new(policy: &RuntimePolicy) -> Self {
        let operations = OperationKind::ALL.map(|operation| {
            let limits = policy.limits(operation);
            Arc::new(OperationAdmission::new(
                limits.max_body_length(),
                limits.max_concurrent_requests(),
            ))
        });
        Self { operations }
    }

    pub(crate) fn update(&self, policy: &RuntimePolicy) {
        for operation in OperationKind::ALL {
            let limits = policy.limits(operation);
            self.operations[operation.index()]
                .update(limits.max_body_length(), limits.max_concurrent_requests());
        }
    }

    pub(crate) async fn acquire(
        &self,
        operation: OperationKind,
        body_length: usize,
        wait_timeout: Duration,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let admission = Arc::clone(&self.operations[operation.index()]);
        self.validate_body_length(operation, body_length)?;

        let permit =
            tokio::time::timeout(wait_timeout, Arc::clone(&admission.semaphore).acquire_owned())
                .await
                .map_err(|_| AdmissionError::CapacityTimeout { wait_timeout })?
                .map_err(|_| AdmissionError::Closed)?;
        Ok(AdmissionPermit {
            admission,
            permit: Some(permit),
        })
    }

    pub(crate) fn validate_body_length(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<(), AdmissionError> {
        let admission = &self.operations[operation.index()];
        let maximum = admission.max_body_length.load(Ordering::Acquire);
        if body_length > maximum {
            return Err(AdmissionError::BodyTooLarge {
                actual: body_length,
                maximum,
            });
        }
        Ok(())
    }
}

/// Reason that a local request did not enter the upstream routing path.
#[derive(Debug)]
pub(crate) enum AdmissionError {
    BodyTooLarge { actual: usize, maximum: usize },
    CapacityTimeout { wait_timeout: Duration },
    Closed,
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
            Self::Closed => formatter.write_str("The request admission controller is closed"),
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
            .acquire(OperationKind::Authentication, 4 * 1024, Duration::from_secs(1))
            .await
            .expect("authentication capacity");
        let authorization = registry
            .acquire(OperationKind::Authorization, 16 * 1024, Duration::from_secs(1))
            .await
            .expect("authorization capacity");

        assert!(matches!(
            registry
                .acquire(OperationKind::Authentication, 4 * 1024 + 1, Duration::from_secs(1),)
                .await,
            Err(AdmissionError::BodyTooLarge { .. })
        ));
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
            .acquire(OperationKind::Authentication, 1, Duration::from_secs(5))
            .await
            .expect("first request capacity");
        let waiting = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                registry
                    .acquire(OperationKind::Authentication, 1, Duration::from_secs(5))
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
    async fn live_limit_decrease_preserves_global_in_flight_accounting() {
        let registry = Arc::new(AdmissionRegistry::new(&policy_with_authentication_limit(1024, 2)));
        let first = registry
            .acquire(OperationKind::Authentication, 1, Duration::from_secs(1))
            .await
            .expect("first permit");
        let second = registry
            .acquire(OperationKind::Authentication, 1, Duration::from_secs(1))
            .await
            .expect("second permit");

        registry.update(&policy_with_authentication_limit(512, 1));
        drop(first);
        assert!(matches!(
            registry
                .acquire(OperationKind::Authentication, 1, Duration::from_millis(1),)
                .await,
            Err(AdmissionError::CapacityTimeout { .. })
        ));
        assert!(matches!(
            registry
                .acquire(OperationKind::Authentication, 513, Duration::from_secs(1),)
                .await,
            Err(AdmissionError::BodyTooLarge { maximum: 512, .. })
        ));

        drop(second);
        registry
            .acquire(OperationKind::Authentication, 1, Duration::from_secs(1))
            .await
            .expect("new limit permits one request");
    }
}
