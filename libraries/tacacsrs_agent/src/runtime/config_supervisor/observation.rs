//! Source and credential observation, candidate application, and publication.
//!
//! These [`ConfigSupervisor`] methods own the continuous observation loops.
//! They read the datastore observation, apply filtered candidates, resolve and
//! publish credential materializations, and maintain credential-change
//! subscriptions. The parent module owns the run loop that joins them.

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
        loop {
            let event = tokio::select! {
                biased;
                () = cancellation.cancelled() => return,
                event = self.next_observation_event() => event,
            };
            match event {
                Ok(ConfigChangeEvent::Changed(change)) => {
                    let _ = tokio::select! {
                        biased;
                        () = cancellation.cancelled() => return,
                        result = self.apply_candidate((*change.config).clone()) => result,
                    };
                    attempt = 0;
                }
                Ok(ConfigChangeEvent::CandidateRejected) => {
                    self.materialization_coordinator
                        .reject_observation(&self.health)
                        .await;
                }
                Ok(ConfigChangeEvent::RestartRequired { required }) => self
                    .health
                    .set_degraded(DegradationReason::RestartRequired, required),
                Err(()) => {
                    self.observation.lock().await.take();
                    attempt = attempt.saturating_add(1);
                    if !self.wait_for_retry(attempt, cancellation).await {
                        return;
                    }
                }
            }
        }
    }

    pub(super) async fn load_and_apply(&self) -> Result<PublicationOutcome, ()> {
        loop {
            match self.next_observation_event().await? {
                ConfigChangeEvent::Changed(change) => {
                    return self.apply_candidate((*change.config).clone()).await
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

    pub(super) async fn apply_candidate(
        &self,
        candidate: TacacsPlus,
    ) -> Result<PublicationOutcome, ()> {
        let coordinator = &self.materialization_coordinator;
        let revision = coordinator.admit_source(candidate.clone()).await;
        let filtered = self.config_filter.filter(candidate).await;
        let Ok(filtered) = filtered else {
            log::warn!(
                "Datastore '{}' configuration candidate was rejected by runtime filtering",
                self.datastore.label(),
            );
            return if coordinator.reject_source(revision, &self.health).await {
                Err(())
            } else {
                Ok(PublicationOutcome::Superseded)
            };
        };
        let Some(attempt) = coordinator
            .accept_filtered_source(
                revision,
                filtered.tacacs_plus,
                filtered.proxy_downstream_obfuscation,
            )
            .await
        else {
            return Ok(PublicationOutcome::Superseded);
        };
        let apply = self.materialize_and_publish(coordinator, attempt).await;
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
            loop {
                let event = tokio::select! {
                    () = cancellation.cancelled() => return,
                    event = stream.next() => event,
                };
                match event {
                    Some(CredentialChangeEvent::Changed(scope)) => {
                        self.health.set_degraded(
                            DegradationReason::CredentialNotificationsUnavailable,
                            false,
                        );
                        self.apply_credential_change(&scope).await;
                    }
                    Some(CredentialChangeEvent::Recovered) => {
                        self.health.set_degraded(
                            DegradationReason::CredentialNotificationsUnavailable,
                            false,
                        );
                        self.apply_credential_change(&CredentialChangeScope::Unknown)
                            .await;
                    }
                    Some(CredentialChangeEvent::Unavailable) | None => {
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

    pub(super) async fn apply_credential_change(&self, scope: &CredentialChangeScope) -> bool {
        let coordinator = &self.materialization_coordinator;
        let Some(attempt) = coordinator
            .observe_credentials(scope, Some(&self.health))
            .await
        else {
            return true;
        };
        let result = self.materialize_and_publish(coordinator, attempt).await;
        result.is_ok()
    }

    pub(super) async fn materialize_and_publish(
        &self,
        coordinator: &MaterializationCoordinator,
        attempt: crate::runtime::materialization_coordinator::MaterializationAttempt,
    ) -> anyhow::Result<PublicationOutcome> {
        let result = match coordinator.materialize(attempt.clone()).await {
            Ok(prepared) => coordinator.publish(prepared, &self.service).await,
            Err(_) => Err(anyhow::anyhow!("credential materialization failed")),
        };
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
