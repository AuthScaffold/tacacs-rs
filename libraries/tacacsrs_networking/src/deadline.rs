//! One absolute budget shared by all stages of a request.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

/// Absolute request expiry. Copying it never renews the budget.
#[derive(Debug, Clone, Copy)]
pub struct RequestDeadline(Instant);

impl RequestDeadline {
    /// Uses an existing absolute expiry.
    #[must_use]
    pub const fn at(expires_at: Instant) -> Self {
        Self(expires_at)
    }

    /// Creates a deadline from a relative budget exactly once.
    ///
    /// # Errors
    /// Returns an error if the budget exceeds the clock's range.
    pub fn after(budget: Duration) -> anyhow::Result<Self> {
        Instant::now()
            .checked_add(budget)
            .map(Self)
            .ok_or_else(|| anyhow::anyhow!("Request deadline exceeds the clock range"))
    }

    /// Returns the absolute expiry.
    #[must_use]
    pub const fn expires_at(self) -> Instant {
        self.0
    }

    /// Returns the unspent portion of this request's budget.
    #[must_use]
    pub fn remaining(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }

    /// Checks expiry before work starts.
    ///
    /// # Errors
    /// Returns [`DeadlineElapsed`] when no budget remains.
    pub fn check(self) -> Result<(), DeadlineElapsed> {
        if Instant::now() >= self.0 {
            Err(DeadlineElapsed)
        } else {
            Ok(())
        }
    }

    /// Runs a stage within the existing budget and drops it on expiry.
    ///
    /// # Errors
    /// Returns [`DeadlineElapsed`] without polling an already-expired stage.
    pub async fn run<Output>(
        self,
        future: impl Future<Output = Output>,
    ) -> Result<Output, DeadlineElapsed> {
        self.check()?;
        tokio::time::timeout_at(self.0, future)
            .await
            .map_err(|_| DeadlineElapsed)
    }
}

/// The absolute request budget is exhausted.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DeadlineElapsed;

impl std::fmt::Display for DeadlineElapsed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("The TACACS+ request deadline expired")
    }
}

impl std::error::Error for DeadlineElapsed {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stages_share_budget_and_expired_work_is_not_polled() {
        let deadline = RequestDeadline::after(Duration::from_secs(5)).unwrap();
        deadline
            .run(tokio::time::sleep(Duration::from_secs(3)))
            .await
            .unwrap();
        assert_eq!(
            deadline
                .run(tokio::time::sleep(Duration::from_secs(3)))
                .await,
            Err(DeadlineElapsed)
        );
        assert_eq!(
            deadline
                .run(async { panic!("expired work must not run") })
                .await,
            Err(DeadlineElapsed)
        );
    }
}
