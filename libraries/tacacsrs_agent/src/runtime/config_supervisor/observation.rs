//! Source and credential observation, candidate application, and publication.
//!
//! These [`ConfigSupervisor`] methods own the continuous observation loops.
//! They read the datastore observation, apply filtered candidates, resolve and
//! publish credential materializations, and maintain credential-change
//! subscriptions. The parent module owns the run loop that joins them.

use futures_util::future::BoxFuture;
use std::sync::Arc;
use crate::runtime::candidate_preparation::{CandidateAdmission, Preparation};

use super::{
    CancellationToken, ChangeNotificationMode, ConfigChangeEvent, ConfigSupervisor,
    CredentialChangeEvent, CredentialChangeScope, DegradationReason, MaterializationCoordinator,
    PublicationOutcome, StreamExt, TacacsPlus,
};

impl ConfigSupervisor {
    /// Maintains a continuous notification source after initial load.
    pub(super) async fn run_notifications(&self, cancellation: &CancellationToken) {
        if self.datastore.runtime_policy().change_notifications == ChangeNotificationMode::None {
            cancellation.cancelled().await;
            return;
        }

        let mut attempt = 0u32;
        let mut candidate: Option<BoxFuture<'_, Result<PublicationOutcome, ()>>> = None;
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return,
                event = self.next_observation_event() => match event {
                    Ok(ConfigChangeEvent::Changed(change)) => {
                        let admission = CandidateAdmission::new(self.service.candidate_limits());
                        drop(candidate.take());
                        if let Ok(admission) = admission {
                            let revision = self.materialization_coordinator.admit_source_at(Arc::clone(&change.config), admission).await;
                            candidate = Some(Box::pin(self.prepare_observation(change.config, revision, admission)));
                        } else {
                            self.materialization_coordinator.reject_observation(&self.health).await;
                        }
                        attempt = 0;
                    }
                    Ok(ConfigChangeEvent::CandidateRejected) => {
                        drop(candidate.take());
                        self.materialization_coordinator
                            .reject_observation(&self.health)
                            .await;
                    }
                    Ok(ConfigChangeEvent::RestartRequired { required }) => self
                        .health
                        .set_degraded(DegradationReason::RestartRequired, required),
                    Err(()) => {
                        drop(candidate.take());
                        self.observation.lock().await.take();
                        attempt = attempt.saturating_add(1);
                        if !self.wait_for_retry(attempt, cancellation).await {
                            return;
                        }
                    }
                },
                _ = async {
                    candidate
                        .as_mut()
                        .expect("the candidate branch requires pending work")
                        .await
                }, if candidate.is_some() => {
                    drop(candidate.take());
                }
            };
        }
    }

    pub(super) async fn load_and_apply(&self) -> Result<PublicationOutcome, ()> {
        loop {
            match self.next_observation_event().await? {
                ConfigChangeEvent::Changed(change) => {
                    return self.apply_observation(change.config).await
                }
                ConfigChangeEvent::CandidateRejected => {
                    self.materialization_coordinator
                        .reject_observation(&self.health)
                        .await;
                    return Err(());
                }
                ConfigChangeEvent::RestartRequired { required } => self
                    .health
                    .set_degraded(DegradationReason::RestartRequired, required),
            }
        }
    }

    async fn next_observation_event(&self) -> Result<ConfigChangeEvent, ()> {
        let mut current = self.observation.lock().await;
        if current.is_none() {
            let opened = self.datastore.observe().await;
            let Ok(opened) = opened else {
                self.materialization_coordinator
                    .source_unavailable(
                        &self.health,
                        self.datastore.runtime_policy().change_notifications
                            == ChangeNotificationMode::Continuous,
                    )
                    .await;
                log::warn!("Datastore '{}' observation could not start", self.datastore.label());
                return Err(());
            };
            *current = Some(opened);
            if self.datastore.runtime_policy().change_notifications
                == ChangeNotificationMode::Continuous
            {
                self.health.set_continuous_notifications_connected(true);
                self.health
                    .set_degraded(DegradationReason::ChangeNotificationsUnavailable, false);
            }
        }
        let Some(observation) = current.as_mut() else {
            return Err(());
        };
        if let Ok(Some(event)) = observation.next().await {
            Ok(event)
        } else {
            current.take();
            self.materialization_coordinator
                .source_unavailable(
                    &self.health,
                    self.datastore.runtime_policy().change_notifications
                        == ChangeNotificationMode::Continuous,
                )
                .await;
            log::warn!("Datastore '{}' observation ended", self.datastore.label());
            Err(())
        }
    }

    #[cfg(test)]
    pub(super) async fn apply_candidate(
        &self,
        candidate: TacacsPlus,
    ) -> Result<PublicationOutcome, ()> {
        self.apply_observation(Arc::new(candidate)).await
    }

    async fn apply_observation(
        &self,
        candidate: Arc<TacacsPlus>,
    ) -> Result<PublicationOutcome, ()> {
        let admission = CandidateAdmission::new(self.service.candidate_limits()).map_err(|_| ())?;
        let revision = self
            .materialization_coordinator
            .admit_source_at(Arc::clone(&candidate), admission)
            .await;
        self.prepare_observation(candidate, revision, admission)
            .await
    }

    async fn prepare_observation(
        &self,
        candidate: Arc<TacacsPlus>,
        revision: crate::SourceRevision,
        admission: CandidateAdmission,
    ) -> Result<PublicationOutcome, ()> {
        let coordinator = &self.materialization_coordinator;
        let accepted = async {
            let preparation = coordinator.acquire_preparation(admission).await?;
            self.service.ensure_open()?;
            anyhow::ensure!(
                coordinator.current_source(revision, admission).await?,
                "candidate preparation was superseded"
            );
            let known_copies = tacacsrs_config::prepare::source_payload_bytes(&candidate)?
                .checked_add(self.config_filter.known_payload_copies(&candidate)?)
                .ok_or_else(|| anyhow::anyhow!("candidate payload size overflow"))?;
            preparation.with_ledger(|ledger| ledger.retain_extra(known_copies))?;
            let filtered = coordinator
                .run_source(revision, admission, self.config_filter.filter((*candidate).clone()))
                .await??;
            let proxy_bytes = u64::try_from(
                filtered
                    .proxy_downstream_obfuscation
                    .shared_secret()?
                    .map_or(0, |secret| secret.expose_secret().len()),
            )?;
            let bytes = tacacsrs_config::prepare::source_payload_bytes(&filtered.tacacs_plus)?
                .checked_add(proxy_bytes)
                .ok_or_else(|| anyhow::anyhow!("candidate payload size overflow"))?;
            preparation.with_ledger(|ledger| ledger.retain_extra(bytes))?;
            let attempt = admission
                .run(coordinator.accept_filtered_source(
                    revision,
                    filtered.tacacs_plus,
                    filtered.proxy_downstream_obfuscation,
                ))
                .await?;
            Ok::<_, anyhow::Error>((attempt, preparation))
        }
        .await;
        let Ok((attempt, preparation)) = accepted else {
            log::warn!(
                "Datastore '{}' configuration candidate was rejected during filtering or projection acceptance",
                self.datastore.label(),
            );
            return if coordinator.reject_source(revision, &self.health).await {
                Err(())
            } else {
                Ok(PublicationOutcome::Superseded)
            };
        };
        let Some(attempt) = attempt else {
            return Ok(PublicationOutcome::Superseded);
        };
        let apply = self
            .materialize_and_publish_in(coordinator, attempt, Some(preparation))
            .await;
        apply.map_err(|_| {
            log::warn!(
                "Failed to prepare or publish the configuration candidate from datastore '{}'",
                self.datastore.label(),
            );
        })
    }

    pub(super) async fn run_credential_notifications(&self, cancellation: &CancellationToken) {
        let Some(source) = self.credential_change_source.as_deref() else {
            cancellation.cancelled().await;
            return;
        };
        let mut attempt = 0u32;
        loop {
            let subscription = tokio::select! {
                () = cancellation.cancelled() => return,
                result = source.subscribe() => result,
            };
            let Ok(mut stream) = subscription else {
                self.materialization_coordinator
                    .credentials_unavailable(&self.health)
                    .await;
                attempt = attempt.saturating_add(1);
                if !self.wait_for_retry(attempt, cancellation).await {
                    return;
                }
                continue;
            };

            attempt = 0;
            let mut candidate: Option<BoxFuture<'_, anyhow::Result<PublicationOutcome>>> = None;
            loop {
                let event = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return,
                    event = stream.next() => event,
                    _ = async { candidate.as_mut().expect("pending credential candidate").await }, if candidate.is_some() => {
                        candidate.take();
                        continue;
                    },
                };
                match event {
                    Some(CredentialChangeEvent::Changed(scope)) => {
                        self.health.set_degraded(
                            DegradationReason::CredentialNotificationsUnavailable,
                            false,
                        );
                        let admission = CandidateAdmission::new(self.service.candidate_limits());
                        let scope = if candidate.is_some() {
                            CredentialChangeScope::Unknown
                        } else {
                            scope
                        };
                        candidate.take();
                        if let (Ok(admission), Some(next)) = (
                            admission,
                            self.materialization_coordinator
                                .observe_credentials(&scope, Some(&self.health))
                                .await,
                        ) {
                            candidate = Some(Box::pin(self.materialize_and_publish(
                                &self.materialization_coordinator,
                                next.with_admission(admission),
                            )));
                        }
                    }
                    Some(CredentialChangeEvent::Recovered) => {
                        self.health.set_degraded(
                            DegradationReason::CredentialNotificationsUnavailable,
                            false,
                        );
                        let admission = CandidateAdmission::new(self.service.candidate_limits());
                        candidate.take();
                        if let (Ok(admission), Some(next)) = (
                            admission,
                            self.materialization_coordinator
                                .observe_credentials(
                                    &CredentialChangeScope::Unknown,
                                    Some(&self.health),
                                )
                                .await,
                        ) {
                            candidate = Some(Box::pin(self.materialize_and_publish(
                                &self.materialization_coordinator,
                                next.with_admission(admission),
                            )));
                        }
                    }
                    Some(CredentialChangeEvent::Unavailable) | None => {
                        drop(candidate.take());
                        self.materialization_coordinator
                            .credentials_unavailable(&self.health)
                            .await;
                        attempt = attempt.saturating_add(1);
                        if !self.wait_for_retry(attempt, cancellation).await {
                            return;
                        }
                        break;
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) async fn apply_credential_change(&self, scope: &CredentialChangeScope) -> bool {
        let Ok(admission) = CandidateAdmission::new(self.service.candidate_limits()) else {
            return false;
        };
        let coordinator = &self.materialization_coordinator;
        let Some(attempt) = coordinator
            .observe_credentials(scope, Some(&self.health))
            .await
        else {
            return true;
        };
        let result = self
            .materialize_and_publish(coordinator, attempt.with_admission(admission))
            .await;
        result.is_ok()
    }

    pub(super) async fn materialize_and_publish(
        &self,
        coordinator: &MaterializationCoordinator,
        attempt: crate::runtime::materialization_coordinator::MaterializationAttempt,
    ) -> anyhow::Result<PublicationOutcome> {
        self.materialize_and_publish_in(coordinator, attempt, None)
            .await
    }

    async fn materialize_and_publish_in(
        &self,
        coordinator: &MaterializationCoordinator,
        attempt: crate::runtime::materialization_coordinator::MaterializationAttempt,
        preparation: Option<Arc<Preparation>>,
    ) -> anyhow::Result<PublicationOutcome> {
        let materialized = async {
            let preparation = match preparation {
                Some(preparation) => preparation,
                None => coordinator.acquire_preparation(attempt.admission()).await?,
            };
            self.service.ensure_open()?;
            coordinator
                .materialize_in(attempt.clone(), preparation)
                .await
        }
        .await;
        let result = match materialized {
            Ok(prepared) => coordinator.publish(prepared, &self.service).await,
            Err(_) => Err(anyhow::anyhow!("credential materialization failed")),
        };
        if matches!(result, Ok(PublicationOutcome::Published)) {
            return result;
        }
        if matches!(result, Ok(PublicationOutcome::Superseded))
            || !coordinator
                .report_credential_result(&attempt, &self.health, result.is_err())
                .await
        {
            return Ok(PublicationOutcome::Superseded);
        }
        result
    }
}
