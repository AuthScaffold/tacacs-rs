//! Proactive credential refresh before prepared lifetimes end.
//!
//! This [`ConfigSupervisor`] loop re-resolves credentials ahead of their
//! prepared expiry, without waiting for a change notification. It is one of the
//! owned futures that the parent run loop joins.

use super::{provider_refresh_delay, CancellationToken, ConfigSupervisor};

impl ConfigSupervisor {
    pub(super) async fn run_provider_refresh(
        &self,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<()> {
        if !self.materialization_coordinator.has_resolver() {
            cancellation.cancelled().await;
            return Ok(());
        }
        let mut changes = self.health.subscribe();
        let mut due: Option<tokio::time::Instant> = None;
        loop {
            let snapshot = changes.borrow_and_update().clone();
            let now = tokio::time::Instant::now();
            let interval = self.service.credential_refresh_interval();
            let remaining = snapshot
                .credential_lifetime()
                .and_then(|lifetime| lifetime.deadline)
                .filter(|deadline| *deadline > now)
                .map(|deadline| deadline.duration_since(now));
            let delay = provider_refresh_delay(interval, remaining);
            let next = now.checked_add(delay).ok_or_else(|| {
                anyhow::anyhow!("Credential refresh interval exceeds the clock range")
            })?;
            let scheduled = due.map_or(next, |current| current.min(next));
            due = Some(scheduled);
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Ok(()),
                () = tokio::time::sleep_until(scheduled) => {
                    let admission = crate::runtime::candidate_preparation::CandidateAdmission::new(self.service.candidate_limits())?;
                    if let Some(attempt) = self.materialization_coordinator.refresh_credentials().await {
                        if self.materialize_and_publish(&self.materialization_coordinator, attempt.with_admission(admission)).await.is_err() {
                            log::warn!("Scheduled credential refresh failed; existing validity limits remain in force");
                        }
                    }
                    due = None;
                }
                change = changes.changed() => { if change.is_err() { return Ok(()); } },
            }
        }
    }
}
