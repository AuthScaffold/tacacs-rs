//! Source and credential staleness and absolute-validity expiry monitors.
//!
//! These [`ConfigSupervisor`] loops capture a deadline from the first stale or
//! non-empty applied catalog and withdraw it when the budget passes. Repeated
//! failures, refreshes, and policy changes do not renew the deadline. The
//! parent run loop joins these owned futures.

use super::{CancellationToken, ConfigSupervisor, DatastoreState, DegradationReason, Duration};

impl ConfigSupervisor {
    pub(super) async fn run_source_expiry(
        &self,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<()> {
        self.run_material_expiry(crate::runtime::MaterialExpiry::Source, cancellation)
            .await
    }

    pub(super) async fn run_credential_expiry(
        &self,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<()> {
        self.run_material_expiry(crate::runtime::MaterialExpiry::Credentials, cancellation)
            .await
    }

    pub(super) async fn run_absolute_credential_expiry(
        &self,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<()> {
        let mut changes = self.health.subscribe();
        let mut last_revision = None;
        loop {
            let snapshot = changes.borrow_and_update().clone();
            if let Some(revision) = snapshot.materialization_revision() {
                last_revision = (snapshot.eligible_server_count() > 0).then_some(revision);
            }
            let lifetime = snapshot.credential_lifetime().filter(|lifetime| {
                !snapshot
                    .degradation_reasons()
                    .contains(&DegradationReason::CredentialsExpired)
                    && (lifetime.validity.valid_from().is_some()
                        || lifetime.validity.valid_until().is_some())
            });
            let wait = async {
                if let (Some(lifetime), Some(_)) = (lifetime, last_revision) {
                    if lifetime.is_valid() {
                        let clock_check = tokio::time::Instant::now() + Duration::from_secs(1);
                        tokio::time::sleep_until(
                            lifetime
                                .deadline
                                .map_or(clock_check, |deadline| deadline.min(clock_check)),
                        )
                        .await;
                    }
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Ok(()),
                () = wait => {
                    if let (Some(lifetime), Some(revision)) = (lifetime, last_revision) {
                        if !lifetime.is_valid() {
                            self.materialization_coordinator.expire_material(crate::runtime::MaterialExpiry::Credentials, revision, &self.service, &self.health).await?;
                        }
                    }
                }
                notification = changes.changed() => { if notification.is_err() { return Ok(()); } },
            }
        }
    }

    async fn run_material_expiry(
        &self,
        kind: crate::runtime::MaterialExpiry,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<()> {
        use crate::runtime::MaterialExpiry;
        let mut changes = self.health.subscribe();
        let mut deadline: Option<tokio::time::Instant> = None;
        let mut last_revision: Option<crate::MaterializationRevision> = None;
        let mut last_source_recovery: Option<crate::SourceRevision> = None;
        loop {
            let snapshot = changes.borrow_and_update().clone();
            let stale = match kind {
                MaterialExpiry::Source => matches!(
                    snapshot.datastore(),
                    DatastoreState::Stale | DatastoreState::Unavailable
                ),
                MaterialExpiry::Credentials => snapshot
                    .degradation_reasons()
                    .contains(&DegradationReason::CredentialsStale),
            };
            let expired = snapshot.degradation_reasons().contains(&match kind {
                MaterialExpiry::Source => DegradationReason::SourceExpired,
                MaterialExpiry::Credentials => DegradationReason::CredentialsExpired,
            });
            if !stale || expired {
                deadline = None;
            }
            let source_recovered = match kind {
                MaterialExpiry::Source => {
                    let recovery = snapshot.source_recovery_revision();
                    let recovered = last_source_recovery.is_some_and(|last| Some(last) != recovery);
                    last_source_recovery = recovery;
                    recovered
                }
                MaterialExpiry::Credentials => false,
            };
            if source_recovered {
                deadline = None;
            }
            if let Some(revision) = snapshot.materialization_revision() {
                if snapshot.eligible_server_count() == 0 {
                    deadline = None;
                    last_revision = None;
                } else {
                    if matches!(kind, MaterialExpiry::Credentials)
                        && last_revision.is_some_and(|last| last != revision)
                    {
                        deadline = None;
                    }
                    last_revision = Some(revision);
                }
            }
            let revision = last_revision.filter(|_| stale && !expired);
            if revision.is_some() && deadline.is_none() {
                deadline = Some(
                    tokio::time::Instant::now()
                        .checked_add(match kind {
                            MaterialExpiry::Source => self.service.source_stale_timeout(),
                            MaterialExpiry::Credentials => self.service.credential_stale_timeout(),
                        })
                        .ok_or_else(|| {
                            anyhow::anyhow!("Source stale budget exceeds the clock range")
                        })?,
                );
            }
            let wait = async {
                if let (Some(deadline), Some(_)) = (deadline, revision) {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Ok(()),
                () = wait => {
                    if let Some(revision) = revision {
                        self.materialization_coordinator.expire_material(kind, revision, &self.service, &self.health).await?;
                    }
                }
                notification = changes.changed() => { if notification.is_err() { return Ok(()); } },
            }
        }
    }
}
