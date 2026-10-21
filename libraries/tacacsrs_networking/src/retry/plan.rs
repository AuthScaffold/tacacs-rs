//! Bounded, conservative retry decisions from explicit runtime inputs.

/// Result class that can cause an attempt on the next eligible server.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AttemptDisposition {
    /// The server returned a valid operation-specific `ERROR` response.
    ServerError,
    /// The request did not reach the server transport.
    NotSent,
    /// The request can have reached the server without a valid response.
    OutcomeUnknown,
}

/// Immutable retry plan for one local operation request.
#[derive(Debug, Clone, Copy)]
pub struct FailoverPlan {
    max_attempts: usize,
}

impl FailoverPlan {
    /// Creates a plan with an explicit attempt budget.
    ///
    /// A budget of one prevents retries. Zero performs no attempts. Only proven
    /// non-delivery or a valid server error can use the remaining budget.
    #[must_use]
    pub const fn new(max_attempts: usize) -> Self {
        Self { max_attempts }
    }

    /// Returns the total attempt budget, including the initial attempt.
    #[must_use]
    pub const fn max_attempts(self) -> usize {
        self.max_attempts
    }

    /// Reports whether a completed attempt permits another attempt.
    #[must_use]
    pub const fn retry_after(
        self,
        completed_attempts: usize,
        disposition: AttemptDisposition,
    ) -> bool {
        if completed_attempts >= self.max_attempts {
            return false;
        }
        match disposition {
            AttemptDisposition::ServerError | AttemptDisposition::NotSent => true,
            AttemptDisposition::OutcomeUnknown => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_failover_never_retries_the_current_request() {
        let plan = FailoverPlan::new(1);

        assert_eq!(plan.max_attempts(), 1);
        assert!(!plan.retry_after(1, AttemptDisposition::ServerError));
    }

    #[test]
    fn bounded_failover_retries_explicit_errors_but_not_unknown_outcomes() {
        let plan = FailoverPlan::new(3);

        assert!(plan.retry_after(1, AttemptDisposition::ServerError));
        assert!(!plan.retry_after(1, AttemptDisposition::OutcomeUnknown));
    }

    #[test]
    fn ordered_safe_retry_never_replays_unknown_outcomes() {
        let plan = FailoverPlan::new(3);
        for completed in 1..=3 {
            assert!(!plan.retry_after(completed, AttemptDisposition::OutcomeUnknown));
            assert_eq!(plan.retry_after(completed, AttemptDisposition::NotSent), completed < 3);
            assert_eq!(plan.retry_after(completed, AttemptDisposition::ServerError), completed < 3);
        }
    }
}
