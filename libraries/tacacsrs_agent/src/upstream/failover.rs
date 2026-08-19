//! Shared failover strategy interpretation and retry safety.

use crate::config::{FailoverStrategy, PolicyService, RuntimePolicy};

use super::OperationKind;

/// Result class that can cause an attempt on the next eligible server.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum AttemptDisposition {
    /// The server returned a valid operation-specific `ERROR` response.
    ServerError,
    /// The request did not reach the server transport.
    NotSent,
    /// The request can have reached the server without a valid response.
    OutcomeUnknown,
}

/// Immutable retry plan for one local operation request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailoverPlan {
    max_attempts: usize,
    retry_unknown_outcome: bool,
}

impl FailoverPlan {
    pub(crate) fn new(
        policy: &RuntimePolicy,
        service: PolicyService,
        operation: OperationKind,
        eligible_server_count: usize,
    ) -> Self {
        let max_attempts = match policy.failover_strategy(service) {
            FailoverStrategy::DeferredFailover => 1,
            FailoverStrategy::OrderedSafeRetry => eligible_server_count.max(1),
        };
        Self {
            max_attempts,
            retry_unknown_outcome: operation != OperationKind::Accounting,
        }
    }

    #[must_use]
    pub(crate) const fn max_attempts(self) -> usize {
        self.max_attempts
    }

    #[must_use]
    pub(crate) const fn retry_after(
        self,
        completed_attempts: usize,
        disposition: AttemptDisposition,
    ) -> bool {
        if completed_attempts >= self.max_attempts {
            return false;
        }
        match disposition {
            AttemptDisposition::ServerError | AttemptDisposition::NotSent => true,
            AttemptDisposition::OutcomeUnknown => self.retry_unknown_outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::config::{OperationPolicies, RuntimePolicy};

    use super::*;

    fn ordered_policy() -> RuntimePolicy {
        RuntimePolicy::new(
            FailoverStrategy::OrderedSafeRetry,
            FailoverStrategy::OrderedSafeRetry,
            OperationPolicies::default(),
            Duration::from_secs(30),
        )
        .expect("test policy")
    }

    #[test]
    fn deferred_failover_never_retries_the_current_request() {
        let plan = FailoverPlan::new(
            &RuntimePolicy::default(),
            PolicyService::ClientApi,
            OperationKind::Authentication,
            3,
        );

        assert_eq!(plan.max_attempts(), 1);
        assert!(!plan.retry_after(1, AttemptDisposition::ServerError));
    }

    #[test]
    fn ordered_failover_retries_explicit_errors_for_accounting() {
        let plan = FailoverPlan::new(
            &ordered_policy(),
            PolicyService::TacacsProxy,
            OperationKind::Accounting,
            3,
        );

        assert!(plan.retry_after(1, AttemptDisposition::ServerError));
        assert!(!plan.retry_after(1, AttemptDisposition::OutcomeUnknown));
    }

    #[test]
    fn ordered_failover_retries_unknown_authentication_outcomes() {
        let plan = FailoverPlan::new(
            &ordered_policy(),
            PolicyService::ClientApi,
            OperationKind::Authentication,
            2,
        );

        assert!(plan.retry_after(1, AttemptDisposition::OutcomeUnknown));
        assert!(!plan.retry_after(2, AttemptDisposition::OutcomeUnknown));
    }
}
