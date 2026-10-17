//! Cancellable datastore loading and change-subscription supervision.
//!
//! The agent owns dependency recovery, credential materialization, and the applied
//! server set. The host supplies a source, configuration filter, and stop future:
//!
//! ```text
//! load candidate -> host filter -> atomic service reload -> health current
//!       |                                      |
//!       +-- failure -> retain known good ------+-> health stale/unavailable
//! ```
//!
//! Datastore policy determines whether initial failure is fatal and whether a
//! observation must be continuously restored. Each session supplies a baseline
//! after observation starts. Coordinated generation/health publication remains
//! a separate migration step.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::StreamExt;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use tacacsrs_config::TacacsPlus;
use tacacsrs_credential_resolution::{
    CredentialChangeEvent, CredentialChangeScope, CredentialChangeSource, CredentialResolver,
};
use tacacsrs_config::source::{
    ChangeNotificationMode, ConfigChangeEvent, ConfigDatastore, ConfigObservation,
    InitialLoadPolicy,
};

use crate::{DatastoreState, DegradationReason, RuntimeHealthPublisher, TacacsClientService};
use crate::runtime::config_filter::TacacsPlusFilter;
use crate::runtime::materialization_coordinator::{MaterializationCoordinator, PublicationOutcome};

/// Prevents repeated short-lived or unchanged responses from causing a busy refresh loop.
const MINIMUM_REFRESH_SPACING: Duration = Duration::from_secs(1);

fn provider_refresh_delay(interval: Duration, remaining: Option<Duration>) -> Duration {
    remaining.map_or(interval, |remaining| interval.min(remaining / 2).max(MINIMUM_REFRESH_SPACING))
}

/// Supplies retry delays without owning asynchronous sleeping.
pub(crate) trait RetryBackoff: Send + Sync {
    /// Returns the delay after a consecutive failure. Attempt numbering starts at one.
    fn delay(&self, attempt: u32) -> Duration;
}

/// Capped exponential retry with bounded downward jitter.
#[derive(Debug)]
pub(crate) struct ExponentialBackoff {
    initial: Duration,
    maximum: Duration,
}

impl ExponentialBackoff {
    /// Creates production datastore retry timing.
    #[must_use]
    pub(crate) const fn production() -> Self {
        Self {
            initial: Duration::from_millis(250),
            maximum: Duration::from_secs(30),
        }
    }
}

impl RetryBackoff for ExponentialBackoff {
    fn delay(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(16);
        let multiplier = 1u32 << exponent;
        let capped = self.initial.saturating_mul(multiplier).min(self.maximum);
        let millis = u64::try_from(capped.as_millis()).unwrap_or(u64::MAX);
        let jitter_span = millis / 5;
        if jitter_span == 0 {
            return capped;
        }

        let jitter = rand::random::<u64>() % jitter_span.saturating_add(1);
        Duration::from_millis(millis.saturating_sub(jitter))
    }
}

/// Applies and continuously refreshes one runtime datastore.
pub struct ConfigSupervisor {
    datastore: Arc<dyn ConfigDatastore>,
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
    config_filter: Arc<dyn TacacsPlusFilter>,
    backoff: Arc<dyn RetryBackoff>,
    materialization_coordinator: Arc<MaterializationCoordinator>,
    credential_change_source: Option<Arc<dyn CredentialChangeSource>>,
    initialized: bool,
    observation: Mutex<Option<Box<dyn ConfigObservation>>>,
}

impl ConfigSupervisor {
    /// Creates a supervisor with production retry timing.
    #[must_use]
    pub fn new(
        datastore: Arc<dyn ConfigDatastore>,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
        config_filter: Arc<dyn TacacsPlusFilter>,
    ) -> Self {
        Self::with_backoff(
            datastore,
            service,
            health,
            config_filter,
            Arc::new(ExponentialBackoff::production()),
        )
    }

    /// Adds a resolver for central credentials before publication.
    #[must_use]
    pub fn with_credential_resolver(
        mut self,
        credential_resolver: Arc<dyn CredentialResolver>,
    ) -> Self {
        self.materialization_coordinator = Arc::new(MaterializationCoordinator::new(
            credential_resolver,
            self.datastore.validation_options(),
        ));
        self.initialized = false;
        self.observation.get_mut().take();
        self
    }

    /// Adds credential change notifications to continuous supervision.
    ///
    /// A credential resolver must also be configured before initialization or execution.
    #[must_use]
    pub fn with_credential_changes(
        mut self,
        credential_change_source: Arc<dyn CredentialChangeSource>,
    ) -> Self {
        self.credential_change_source = Some(credential_change_source);
        self
    }

    /// Applies initial configuration before listeners start, unless `stop` completes.
    ///
    /// A later [`Self::run_until`] call preserves this initialization and starts
    /// both configuration and credential supervision.
    ///
    /// # Errors
    /// Returns a sanitized error when provider configuration or fail-fast preparation fails.
    pub async fn initialize_until(
        &mut self,
        stop: impl Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        self.validate_provider()?;
        if self.initialized {
            return Ok(());
        }
        self.observation.get_mut().take();
        let cancellation = CancellationToken::new();
        tokio::select! {
            biased;
            () = stop => {
                self.observation.get_mut().take();
                return Ok(());
            },
            result = self.load_initial(&cancellation) => result?,
        }
        self.initialized = true;
        Ok(())
    }

    /// Owns configuration and credential supervision until the host stops it.
    ///
    /// Cancellation interrupts source loading, filtering, resolution, publication
    /// lock acquisition, and retry waits. This method installs no signal handlers.
    ///
    /// # Errors
    /// Returns an error when provider configuration or fail-fast initialization fails.
    pub async fn run_until(mut self, stop: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
        self.validate_provider()?;
        if !self.initialized {
            self.observation.get_mut().take();
        }
        let cancellation = CancellationToken::new();
        let _cancel_on_drop = cancellation.clone().drop_guard();
        tokio::select! {
            biased;
            () = stop => Ok(()),
            result = self.run(&cancellation) => result,
        }
    }

    fn validate_provider(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.credential_change_source.is_none()
                || self.materialization_coordinator.has_resolver(),
            "Credential change notifications require a credential resolver",
        );
        Ok(())
    }

    fn with_backoff(
        datastore: Arc<dyn ConfigDatastore>,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
        config_filter: Arc<dyn TacacsPlusFilter>,
        backoff: Arc<dyn RetryBackoff>,
    ) -> Self {
        Self::with_backoff_and_provider(
            datastore,
            service,
            health,
            config_filter,
            backoff,
            None,
            None,
        )
    }

    #[cfg(test)]
    fn with_backoff_and_resolver(
        datastore: Arc<dyn ConfigDatastore>,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
        config_filter: Arc<dyn TacacsPlusFilter>,
        backoff: Arc<dyn RetryBackoff>,
        credential_resolver: Option<Arc<dyn CredentialResolver>>,
    ) -> Self {
        Self::with_backoff_and_provider(
            datastore,
            service,
            health,
            config_filter,
            backoff,
            credential_resolver,
            None,
        )
    }

    fn with_backoff_and_provider(
        datastore: Arc<dyn ConfigDatastore>,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
        config_filter: Arc<dyn TacacsPlusFilter>,
        backoff: Arc<dyn RetryBackoff>,
        credential_resolver: Option<Arc<dyn CredentialResolver>>,
        credential_change_source: Option<Arc<dyn CredentialChangeSource>>,
    ) -> Self {
        let materialization_coordinator = Arc::new(match credential_resolver {
            Some(resolver) => {
                MaterializationCoordinator::new(resolver, datastore.validation_options())
            }
            None => MaterializationCoordinator::without_resolver(datastore.validation_options()),
        });
        Self {
            datastore,
            service,
            health,
            config_filter,
            backoff,
            materialization_coordinator,
            credential_change_source,
            initialized: false,
            observation: Mutex::new(None),
        }
    }

    /// Loads and applies the initial snapshot according to datastore policy.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when a fail-fast datastore cannot supply a
    /// valid candidate. Cancellation is a successful shutdown outcome.
    async fn load_initial(&self, cancellation: &CancellationToken) -> anyhow::Result<()> {
        let policy = self.datastore.runtime_policy().initial_load;
        let mut attempt = 0u32;

        loop {
            self.health.set_datastore(DatastoreState::Loading);
            let result = tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                result = self.load_and_apply() => result,
            };

            match result {
                Ok(PublicationOutcome::Published) => {
                    return Ok(());
                }
                Ok(PublicationOutcome::Superseded) => {}
                Err(()) if policy == InitialLoadPolicy::FailFast => {
                    self.observation.lock().await.take();
                    anyhow::bail!(
                        "Datastore '{}' did not supply a valid initial configuration",
                        self.datastore.label(),
                    );
                }
                Err(()) => {
                    self.observation.lock().await.take();
                    attempt = attempt.saturating_add(1);
                    log::warn!(
                        "Datastore '{}' initial configuration is unavailable. The daemon retries.",
                        self.datastore.label(),
                    );
                    if !self.wait_for_retry(attempt, cancellation).await {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Runs the initial load and then maintains notifications until canceled.
    ///
    /// # Errors
    ///
    /// Returns an error only when fail-fast initial loading fails.
    async fn run(&self, cancellation: &CancellationToken) -> anyhow::Result<()> {
        if !self.initialized {
            self.load_initial(cancellation).await?;
        }
        if cancellation.is_cancelled() {
            return Ok(());
        }
        tokio::try_join!(
            async {
                self.run_notifications(cancellation).await;
                Ok(())
            },
            async {
                self.run_credential_notifications(cancellation).await;
                Ok(())
            },
            self.run_source_expiry(cancellation),
            self.run_credential_expiry(cancellation),
            self.run_absolute_credential_expiry(cancellation),
            self.run_provider_refresh(cancellation),
        )?;
        Ok(())
    }

    async fn run_source_expiry(&self, cancellation: &CancellationToken) -> anyhow::Result<()> {
        self.run_material_expiry(crate::runtime::MaterialExpiry::Source, cancellation)
            .await
    }

    async fn run_provider_refresh(&self, cancellation: &CancellationToken) -> anyhow::Result<()> {
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
                    if let Some(attempt) = self.materialization_coordinator.refresh_credentials().await {
                        if self.materialize_and_publish(&self.materialization_coordinator, attempt).await.is_err() {
                            log::warn!("Scheduled credential refresh failed; existing validity limits remain in force");
                        }
                    }
                    due = None;
                }
                change = changes.changed() => { if change.is_err() { return Ok(()); } },
            }
        }
    }

    async fn run_credential_expiry(&self, cancellation: &CancellationToken) -> anyhow::Result<()> {
        self.run_material_expiry(crate::runtime::MaterialExpiry::Credentials, cancellation)
            .await
    }

    async fn run_absolute_credential_expiry(
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

    /// Maintains a continuous notification source after initial load.
    async fn run_notifications(&self, cancellation: &CancellationToken) {
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
                        drop(candidate.take());
                        candidate = Some(Box::pin(self.apply_candidate((*change.config).clone())));
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

    async fn load_and_apply(&self) -> Result<PublicationOutcome, ()> {
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

    async fn apply_candidate(&self, candidate: TacacsPlus) -> Result<PublicationOutcome, ()> {
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

    async fn run_credential_notifications(&self, cancellation: &CancellationToken) {
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

    async fn apply_credential_change(&self, scope: &CredentialChangeScope) -> bool {
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

    async fn materialize_and_publish(
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

    async fn wait_for_retry(&self, attempt: u32, cancellation: &CancellationToken) -> bool {
        let delay = self.backoff.delay(attempt);
        tokio::select! {
            () = cancellation.cancelled() => false,
            () = tokio::time::sleep(delay) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use crate::{EnabledServices, ServiceConfig};
    use tacacsrs_config::{TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
    use tacacsrs_config::{EpskSupportedHash, Tls13Epsk, TlsClientClientIdentity};
    use tacacsrs_credential_resolution::{
        CredentialChangeError, CredentialChangeEvent, CredentialChangeScope,
        CredentialChangeSource, CredentialChangeStream, CredentialKind, CredentialReference,
        CredentialRequest, ProviderErrorKind, ResolutionError, ResolvedCredential, SecretBytes,
    };
    use tacacsrs_config::source::{ConfigChangeStream, DatastoreRuntimePolicy};
    use tokio::time::timeout;

    use super::*;
    use crate::runtime::config_filter::NoopTacacsPlusFilter;

    #[test]
    fn refresh_delay_is_early_but_never_busy_spins() {
        let interval = Duration::from_secs(60);
        assert_eq!(provider_refresh_delay(interval, None), interval);
        assert_eq!(provider_refresh_delay(interval, Some(Duration::from_secs(300))), interval);
        assert_eq!(
            provider_refresh_delay(interval, Some(Duration::from_secs(20))),
            Duration::from_secs(10)
        );
        assert_eq!(
            provider_refresh_delay(interval, Some(Duration::from_millis(10))),
            MINIMUM_REFRESH_SPACING
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum LoadStep {
        Error,
        Pending,
        Config(usize),
        CentralConfig(usize),
    }

    #[derive(Debug, Clone, Copy)]
    enum SubscriptionStep {
        Error,
        Empty,
        Pending,
        RejectedThenPending,
        RestartThenPending,
    }

    struct ScriptedDatastore {
        policy: DatastoreRuntimePolicy,
        loads: Mutex<VecDeque<LoadStep>>,
        subscriptions: Mutex<VecDeque<SubscriptionStep>>,
        load_count: AtomicUsize,
        subscribe_count: AtomicUsize,
    }

    impl ScriptedDatastore {
        fn new(
            policy: DatastoreRuntimePolicy,
            loads: impl IntoIterator<Item = LoadStep>,
            subscriptions: impl IntoIterator<Item = SubscriptionStep>,
        ) -> Self {
            Self {
                policy,
                loads: Mutex::new(loads.into_iter().collect()),
                subscriptions: Mutex::new(subscriptions.into_iter().collect()),
                load_count: AtomicUsize::new(0),
                subscribe_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ConfigDatastore for ScriptedDatastore {
        async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
            let events = if self.policy.change_notifications == ChangeNotificationMode::Continuous {
                self.open_events()?
            } else {
                Box::pin(tokio_stream::empty()) as ConfigChangeStream
            };
            let config = Arc::new(self.load().await?);
            let baseline = ConfigChangeEvent::Changed(tacacsrs_config::source::ConfigChange {
                delta: tacacsrs_config::source::ConfigDelta::diff(None, &config),
                config,
            });
            Ok(Box::new(ScriptedObservation {
                baseline: Some(baseline),
                events,
            }))
        }

        fn runtime_policy(&self) -> DatastoreRuntimePolicy {
            self.policy
        }

        async fn load(&self) -> anyhow::Result<TacacsPlus> {
            self.load_count.fetch_add(1, Ordering::Relaxed);
            let step = self
                .loads
                .lock()
                .expect("loads lock")
                .pop_front()
                .unwrap_or(LoadStep::Error);
            match step {
                LoadStep::Error => anyhow::bail!("scripted load failure"),
                LoadStep::Pending => std::future::pending().await,
                LoadStep::Config(server_count) => Ok(test_config(server_count)),
                LoadStep::CentralConfig(server_count) => Ok(central_test_config(server_count)),
            }
        }

        fn label(&self) -> &'static str {
            "scripted"
        }
    }

    impl ScriptedDatastore {
        fn open_events(&self) -> anyhow::Result<ConfigChangeStream> {
            self.subscribe_count.fetch_add(1, Ordering::Relaxed);
            let step = self
                .subscriptions
                .lock()
                .expect("subscriptions lock")
                .pop_front()
                .unwrap_or(SubscriptionStep::Pending);
            match step {
                SubscriptionStep::Error => anyhow::bail!("scripted subscription failure"),
                SubscriptionStep::Empty => Ok(Box::pin(tokio_stream::empty())),
                SubscriptionStep::Pending => Ok(Box::pin(tokio_stream::pending())),
                SubscriptionStep::RejectedThenPending => Ok(Box::pin(
                    tokio_stream::once(ConfigChangeEvent::CandidateRejected)
                        .chain(tokio_stream::pending()),
                )),
                SubscriptionStep::RestartThenPending => Ok(Box::pin(
                    tokio_stream::once(ConfigChangeEvent::RestartRequired { required: true })
                        .chain(tokio_stream::pending()),
                )),
            }
        }
    }

    #[derive(Debug)]
    struct FixedBackoff(Duration);

    struct OwnedSource {
        events: Mutex<Option<tokio::sync::mpsc::Receiver<ConfigChangeEvent>>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
        opens: AtomicUsize,
    }

    struct OwnedObservation {
        events: tokio::sync::mpsc::Receiver<ConfigChangeEvent>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for OwnedObservation {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[async_trait]
    impl ConfigObservation for OwnedObservation {
        async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
            Ok(self.events.recv().await)
        }
    }

    #[async_trait]
    impl ConfigDatastore for OwnedSource {
        fn runtime_policy(&self) -> DatastoreRuntimePolicy {
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::FailFast,
                ChangeNotificationMode::Continuous,
            )
        }

        async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            let events = self
                .events
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| anyhow::anyhow!("the owned observation is unavailable"))?;
            Ok(Box::new(OwnedObservation {
                events,
                dropped: self.dropped.clone(),
            }))
        }

        async fn load(&self) -> anyhow::Result<TacacsPlus> {
            panic!("runtime must use observation");
        }
        fn label(&self) -> &'static str {
            "owned-test"
        }
    }

    struct ScriptedObservation {
        baseline: Option<ConfigChangeEvent>,
        events: ConfigChangeStream,
    }

    #[async_trait]
    impl ConfigObservation for ScriptedObservation {
        async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
            if let Some(baseline) = self.baseline.take() {
                return Ok(Some(baseline));
            }
            Ok(self.events.next().await)
        }
    }

    impl RetryBackoff for FixedBackoff {
        fn delay(&self, _attempt: u32) -> Duration {
            self.0
        }
    }

    struct SelectiveResolver {
        rejected_server: Mutex<Option<String>>,
    }

    struct InitiallyUnavailableResolver {
        failures_remaining: AtomicUsize,
    }

    struct CountingResolver {
        resolved_servers: Mutex<Vec<String>>,
    }

    struct BlockingResolver {
        entered: tokio::sync::Notify,
    }

    struct PausingRefreshResolver {
        paused: std::sync::atomic::AtomicBool,
        release: tokio::sync::Notify,
    }

    struct StallingResolver {
        stalled: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        cancelled: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl CredentialResolver for StallingResolver {
        async fn resolve(
            &self,
            _request: &CredentialRequest,
        ) -> Result<ResolvedCredential, ResolutionError> {
            if self.stalled.load(Ordering::Acquire) {
                let _pending = PendingDrop(Arc::clone(&self.cancelled));
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(ResolvedCredential::SymmetricKey(
                tacacsrs_credential_resolution::SymmetricKeyMaterial {
                    validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
                    key_format: None,
                    key: SecretBytes::new(b"stall-test-material-long-enough".to_vec()),
                },
            ))
        }
    }

    #[async_trait]
    impl CredentialResolver for PausingRefreshResolver {
        async fn resolve(
            &self,
            _request: &CredentialRequest,
        ) -> Result<ResolvedCredential, ResolutionError> {
            if self.paused.load(Ordering::Acquire) {
                self.release.notified().await;
            }
            Ok(ResolvedCredential::SymmetricKey(
                tacacsrs_credential_resolution::SymmetricKeyMaterial {
                    validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
                    key_format: None,
                    key: SecretBytes::new(b"refresh-test-material-long-enough".to_vec()),
                },
            ))
        }
    }

    struct ValidityResolver(Mutex<tacacsrs_credential_resolution::CredentialValidity>);

    #[async_trait]
    impl CredentialResolver for ValidityResolver {
        async fn resolve(
            &self,
            _request: &CredentialRequest,
        ) -> Result<ResolvedCredential, ResolutionError> {
            Ok(ResolvedCredential::SymmetricKey(
                tacacsrs_credential_resolution::SymmetricKeyMaterial {
                    validity: *self.0.lock().unwrap(),
                    key_format: None,
                    key: SecretBytes::new(b"validity-test-material-long-enough".to_vec()),
                },
            ))
        }
    }

    struct PausingFilter {
        paused: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        cancelled: Arc<AtomicUsize>,
    }

    struct PendingDrop(Arc<AtomicUsize>);

    impl Drop for PendingDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }

    struct ReorderedFilter {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        reject_old: bool,
    }

    impl TacacsPlusFilter for ReorderedFilter {
        fn filter(
            &self,
            candidate: TacacsPlus,
        ) -> futures_util::future::BoxFuture<'_, anyhow::Result<crate::runtime::FilteredTacacsPlus>>
        {
            Box::pin(async move {
                if candidate.server.len() == 1 {
                    self.entered.notify_one();
                    self.release.notified().await;
                    anyhow::ensure!(!self.reject_old, "rejected old candidate");
                }
                NoopTacacsPlusFilter::default().filter(candidate).await
            })
        }
    }

    impl TacacsPlusFilter for PausingFilter {
        fn filter(
            &self,
            candidate: TacacsPlus,
        ) -> futures_util::future::BoxFuture<'_, anyhow::Result<crate::runtime::FilteredTacacsPlus>>
        {
            Box::pin(async move {
                if !self.paused.swap(true, Ordering::AcqRel) {
                    let _pending = PendingDrop(Arc::clone(&self.cancelled));
                    self.entered.notify_one();
                    std::future::pending::<()>().await;
                }
                NoopTacacsPlusFilter::default().filter(candidate).await
            })
        }
    }

    #[async_trait]
    impl CredentialResolver for BlockingResolver {
        async fn resolve(
            &self,
            _request: &CredentialRequest,
        ) -> Result<ResolvedCredential, ResolutionError> {
            self.entered.notify_one();
            std::future::pending().await
        }
    }

    enum CredentialSubscriptionStep {
        Error,
        Events(Vec<CredentialChangeEvent>),
    }

    struct ScriptedCredentialChangeSource {
        subscriptions: Mutex<VecDeque<CredentialSubscriptionStep>>,
    }

    #[async_trait]
    impl CredentialChangeSource for ScriptedCredentialChangeSource {
        async fn subscribe(&self) -> Result<CredentialChangeStream, CredentialChangeError> {
            let step = self
                .subscriptions
                .lock()
                .expect("credential subscriptions lock")
                .pop_front()
                .unwrap_or(CredentialSubscriptionStep::Events(Vec::new()));
            match step {
                CredentialSubscriptionStep::Error => Err(CredentialChangeError),
                CredentialSubscriptionStep::Events(events) => {
                    Ok(Box::pin(tokio_stream::iter(events).chain(tokio_stream::pending())))
                }
            }
        }
    }

    #[async_trait]
    impl CredentialResolver for InitiallyUnavailableResolver {
        async fn resolve(
            &self,
            request: &CredentialRequest,
        ) -> Result<ResolvedCredential, ResolutionError> {
            #[allow(
                deprecated,
                reason = "AtomicUsize::try_update is newer than the Rust 1.88 MSRV."
            )]
            let should_fail = self
                .failures_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| count.checked_sub(1))
                .is_ok();
            if should_fail {
                return Err(ResolutionError::provider(
                    ProviderErrorKind::Unavailable,
                    request.context(),
                ));
            }
            Ok(ResolvedCredential::SymmetricKey(
                tacacsrs_credential_resolution::SymmetricKeyMaterial {
                    validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
                    key_format: None,
                    key: SecretBytes::new(b"resolved-after-retry".to_vec()),
                },
            ))
        }
    }

    #[async_trait]
    impl CredentialResolver for SelectiveResolver {
        async fn resolve(
            &self,
            request: &CredentialRequest,
        ) -> Result<ResolvedCredential, ResolutionError> {
            if self
                .rejected_server
                .lock()
                .expect("resolver lock")
                .as_deref()
                == Some(request.context().server_name())
            {
                return Err(ResolutionError::provider(
                    ProviderErrorKind::Unavailable,
                    request.context(),
                ));
            }
            Ok(ResolvedCredential::SymmetricKey(
                tacacsrs_credential_resolution::SymmetricKeyMaterial {
                    validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
                    key_format: None,
                    key: SecretBytes::new(b"resolved-supervisor-secret".to_vec()),
                },
            ))
        }
    }

    #[async_trait]
    impl CredentialResolver for CountingResolver {
        async fn resolve(
            &self,
            request: &CredentialRequest,
        ) -> Result<ResolvedCredential, ResolutionError> {
            self.resolved_servers
                .lock()
                .expect("resolved servers lock")
                .push(request.context().server_name().to_owned());
            Ok(ResolvedCredential::SymmetricKey(
                tacacsrs_credential_resolution::SymmetricKeyMaterial {
                    validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
                    key_format: None,
                    key: SecretBytes::new(b"resolved-counting-secret".to_vec()),
                },
            ))
        }
    }

    #[test]
    fn exponential_backoff_stays_within_jitter_floor_and_maximum() {
        let backoff = ExponentialBackoff {
            initial: Duration::from_millis(250),
            maximum: Duration::from_secs(30),
        };

        for attempt in 1..=24 {
            let exponent = (attempt - 1).min(16);
            let capped = Duration::from_millis(250)
                .saturating_mul(1u32 << exponent)
                .min(Duration::from_secs(30));
            let delay = backoff.delay(attempt);

            assert!(delay >= capped.saturating_mul(4) / 5);
            assert!(delay <= capped);
        }
    }

    fn test_config(server_count: usize) -> TacacsPlus {
        (0..server_count)
            .fold(TacacsPlusBuilder::new(), |builder, index| {
                builder.with_server_builder(
                    TacacsPlusServerBuilder::new(
                        format!("server-{index}"),
                        TacacsPlusServerType::all(),
                        format!("192.0.2.{}", index + 1),
                        49,
                    )
                    .with_shared_secret("test-secret"),
                )
            })
            .build()
            .expect("test configuration")
    }

    fn central_test_config(server_count: usize) -> TacacsPlus {
        let mut config = test_config(server_count);
        for (index, server) in config.server.iter_mut().enumerate() {
            server.shared_secret = None;
            server.port = 449;
            server.client_identity = Some(TlsClientClientIdentity {
                credentials_reference: None,
                certificate: None,
                tls13_epsk: Some(Tls13Epsk {
                    inline_definition: None,
                    central_keystore_reference: Some(format!("object-{index}")),
                    external_identity: "client".to_owned(),
                    hash: EpskSupportedHash::Sha256,
                    context: None,
                    target_protocol: None,
                    target_kdf: None,
                    psk_dhe_ke_groups: Vec::new(),
                }),
            });
        }
        config
    }

    fn supervisor(
        datastore: Arc<ScriptedDatastore>,
        backoff: Duration,
    ) -> (ConfigSupervisor, RuntimeHealthPublisher, Arc<TacacsClientService>) {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let service = Arc::new(
            TacacsClientService::waiting_for_configuration(
                ServiceConfig {
                    local_services: tacacsrs_config::tacacsrs::LocalServices::default(),
                    tacacs_plus: TacacsPlus::empty(),
                    validation_options: datastore.validation_options(),
                    runtime_policy: crate::RuntimePolicy::new(
                        crate::FailoverStrategy::default(),
                        crate::FailoverStrategy::default(),
                        crate::OperationPolicies::default(),
                        Duration::from_secs(1),
                    )
                    .expect("test runtime policy"),
                    disable_certificate_verification: false,
                },
                health.clone(),
            )
            .expect("service"),
        );
        let supervisor = ConfigSupervisor::with_backoff(
            datastore,
            Arc::clone(&service),
            health.clone(),
            Arc::new(NoopTacacsPlusFilter::default()),
            Arc::new(FixedBackoff(backoff)),
        );
        (supervisor, health, service)
    }

    #[tokio::test(start_paused = true)]
    async fn provider_material_refreshes_before_expiry_without_notifications() {
        use std::time::SystemTime;
        use tacacsrs_credential_resolution::CredentialValidity;
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(1)],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let resolver = Arc::new(ValidityResolver(Mutex::new(
            CredentialValidity::new(None, Some(SystemTime::now() + Duration::from_secs(20)))
                .unwrap(),
        )));
        let mut supervisor = supervisor.with_credential_resolver(resolver.clone());
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        let original = health.snapshot().materialization_revision().unwrap();
        *resolver.0.lock().unwrap() = CredentialValidity::unbounded();
        let stop = CancellationToken::new();
        let running = supervisor.run_until(stop.cancelled());
        tokio::pin!(running);
        assert!(futures_util::poll!(&mut running).is_pending());
        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(futures_util::poll!(&mut running).is_pending());
        let refreshed = health.snapshot().materialization_revision().unwrap();
        assert_eq!(refreshed.source(), original.source());
        assert!(
            refreshed.credentials().value() > original.credentials().value(),
            "provider must refresh before expiry without an invalidation event"
        );
        assert_eq!(health.snapshot().credential_validity(), Some(CredentialValidity::unbounded()));
        assert_eq!(service.server_count(), 1);
        stop.cancel();
        running.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn scheduled_revalidation_does_not_extend_unchanged_provider_validity() {
        use std::time::SystemTime;
        use tacacsrs_credential_resolution::CredentialValidity;
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(1)],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let resolver = Arc::new(ValidityResolver(Mutex::new(
            CredentialValidity::new(None, Some(SystemTime::now() + Duration::from_secs(20)))
                .unwrap(),
        )));
        let mut supervisor = supervisor.with_credential_resolver(resolver);
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        let original = health.snapshot().credential_lifetime().unwrap();
        let stop = CancellationToken::new();
        let refresh = supervisor.run_provider_refresh(&stop);
        tokio::pin!(refresh);
        assert!(futures_util::poll!(&mut refresh).is_pending());
        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(futures_util::poll!(&mut refresh).is_pending());
        assert_eq!(health.snapshot().credential_lifetime(), Some(original));
        let expiry = supervisor.run_absolute_credential_expiry(&stop);
        tokio::pin!(expiry);
        assert!(futures_util::poll!(&mut expiry).is_pending());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(futures_util::poll!(&mut expiry).is_pending());
        assert_eq!(service.server_count(), 0);
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CredentialsExpired));
        stop.cancel();
        refresh.await.unwrap();
        expiry.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn scheduled_refresh_policy_does_not_postpone_due_work_or_poll_inline_material() {
        for referenced in [false, true] {
            let datastore = Arc::new(ScriptedDatastore::new(
                DatastoreRuntimePolicy::new(
                    InitialLoadPolicy::FailFast,
                    ChangeNotificationMode::None,
                ),
                [if referenced {
                    LoadStep::CentralConfig(1)
                } else {
                    LoadStep::Config(1)
                }],
                [],
            ));
            let (supervisor, _, service) = supervisor(datastore, Duration::ZERO);
            let resolver = Arc::new(CountingResolver {
                resolved_servers: Mutex::new(Vec::new()),
            });
            let mut supervisor = supervisor.with_credential_resolver(resolver.clone());
            let policy = |seconds| {
                tacacsrs_config::policy::parse_runtime_policy(format!(
                r#"{{"tacacsrs:runtime-policy":{{"credential-refresh-interval-seconds":{seconds}}}}}"#).as_bytes()).unwrap()
            };
            service
                .apply_policy_candidate(Some(&policy(2)))
                .await
                .unwrap();
            supervisor
                .initialize_until(std::future::pending())
                .await
                .unwrap();
            let stop = CancellationToken::new();
            let refresh = supervisor.run_provider_refresh(&stop);
            tokio::pin!(refresh);
            assert!(futures_util::poll!(&mut refresh).is_pending());
            tokio::time::advance(Duration::from_secs(1)).await;
            service
                .apply_policy_candidate(Some(&policy(100)))
                .await
                .unwrap();
            assert!(futures_util::poll!(&mut refresh).is_pending());
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(futures_util::poll!(&mut refresh).is_pending());
            assert_eq!(
                resolver.resolved_servers.lock().unwrap().len(),
                if referenced {
                    2
                } else {
                    0
                }
            );
            tokio::time::advance(Duration::from_secs(99)).await;
            assert!(futures_util::poll!(&mut refresh).is_pending());
            assert_eq!(
                resolver.resolved_servers.lock().unwrap().len(),
                if referenced {
                    2
                } else {
                    0
                }
            );
            service
                .apply_policy_candidate(Some(&policy(1)))
                .await
                .unwrap();
            assert!(futures_util::poll!(&mut refresh).is_pending());
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(futures_util::poll!(&mut refresh).is_pending());
            assert_eq!(
                resolver.resolved_servers.lock().unwrap().len(),
                if referenced {
                    3
                } else {
                    0
                }
            );
            stop.cancel();
            refresh.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn scheduled_refresh_failure_expires_and_recovers_without_notifications() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(1)],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let resolver = Arc::new(SelectiveResolver {
            rejected_server: Mutex::new(None),
        });
        let mut supervisor = supervisor.with_credential_resolver(resolver.clone());
        let policy = tacacsrs_config::policy::parse_runtime_policy(br#"{"tacacsrs:runtime-policy":{"credential-refresh-interval-seconds":2,"credential-stale-timeout-seconds":2}}"#).unwrap();
        service.apply_policy_candidate(Some(&policy)).await.unwrap();
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        let original = health.snapshot().materialization_revision().unwrap();
        *resolver.rejected_server.lock().unwrap() = Some("server-0".to_owned());
        let stop = CancellationToken::new();
        let refresh = supervisor.run_provider_refresh(&stop);
        tokio::pin!(refresh);
        let expiry = supervisor.run_credential_expiry(&stop);
        tokio::pin!(expiry);
        assert!(futures_util::poll!(&mut refresh).is_pending());
        assert!(futures_util::poll!(&mut expiry).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(futures_util::poll!(&mut refresh).is_pending());
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CredentialResolutionFailed));
        assert!(futures_util::poll!(&mut expiry).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(futures_util::poll!(&mut expiry).is_pending());
        assert_eq!(service.server_count(), 0);
        *resolver.rejected_server.lock().unwrap() = None;
        assert!(futures_util::poll!(&mut refresh).is_pending());
        let recovered = health.snapshot();
        assert_eq!(service.server_count(), 1);
        assert_eq!(recovered.materialization_revision().unwrap().source(), original.source());
        assert!(!recovered
            .degradation_reasons()
            .contains(&DegradationReason::CredentialsExpired));
        stop.cancel();
        refresh.await.unwrap();
        expiry.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn pending_scheduled_refresh_does_not_block_expiry_or_host_stop() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(1)],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let resolver = Arc::new(PausingRefreshResolver {
            paused: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
        });
        let mut supervisor = supervisor.with_credential_resolver(resolver.clone());
        let policy = tacacsrs_config::policy::parse_runtime_policy(br#"{"tacacsrs:runtime-policy":{"credential-refresh-interval-seconds":1,"credential-stale-timeout-seconds":2}}"#).unwrap();
        service.apply_policy_candidate(Some(&policy)).await.unwrap();
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        resolver.paused.store(true, Ordering::Release);
        let coordinator = supervisor.materialization_coordinator.clone();
        let stop = CancellationToken::new();
        let running = supervisor.run_until(stop.cancelled());
        tokio::pin!(running);
        assert!(futures_util::poll!(&mut running).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut running).is_pending());
        assert!(!health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CredentialsStale));
        coordinator.credentials_unavailable(&health).await;
        assert!(futures_util::poll!(&mut running).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(futures_util::poll!(&mut running).is_pending());
        assert_eq!(service.server_count(), 0);
        stop.cancel();
        running.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn absolute_validity_expires_without_notifications_and_after_source_withdrawal() {
        use std::time::SystemTime;
        use tacacsrs_credential_resolution::CredentialValidity;
        for source_first in [false, true] {
            let datastore = Arc::new(ScriptedDatastore::new(
                DatastoreRuntimePolicy::new(
                    InitialLoadPolicy::FailFast,
                    ChangeNotificationMode::None,
                ),
                [],
                [],
            ));
            let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
            let resolver = Arc::new(ValidityResolver(Mutex::new(
                CredentialValidity::new(None, Some(SystemTime::now() + Duration::from_secs(2)))
                    .unwrap(),
            )));
            let supervisor = supervisor.with_credential_resolver(resolver.clone());
            supervisor
                .apply_candidate(central_test_config(1))
                .await
                .unwrap();
            let original = health.snapshot().materialization_revision().unwrap();
            assert!(
                health.set_listener(crate::RuntimeService::ClientApi, crate::ListenerState::Bound)
            );
            assert!(health.snapshot().is_readiness_serving());
            let cancellation = CancellationToken::new();
            let monitor = supervisor.run_absolute_credential_expiry(&cancellation);
            tokio::pin!(monitor);
            assert!(futures_util::poll!(&mut monitor).is_pending());
            if source_first {
                supervisor
                    .materialization_coordinator
                    .source_unavailable(&health, true)
                    .await;
                supervisor
                    .materialization_coordinator
                    .expire_source(original, &service, &health)
                    .await
                    .unwrap();
                assert!(futures_util::poll!(&mut monitor).is_pending());
            }
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(futures_util::poll!(&mut monitor).is_pending());
            assert_eq!(service.server_count(), 0);
            assert!(health
                .snapshot()
                .degradation_reasons()
                .contains(&DegradationReason::CredentialsExpired));
            assert_eq!(
                health
                    .snapshot()
                    .degradation_reasons()
                    .contains(&DegradationReason::SourceExpired),
                source_first
            );
            assert!(!health.snapshot().is_readiness_serving());
            assert!(health.snapshot().is_liveness_serving());
            *resolver.0.lock().unwrap() =
                CredentialValidity::new(None, Some(SystemTime::UNIX_EPOCH)).unwrap();
            assert!(
                !supervisor
                    .apply_credential_change(&CredentialChangeScope::Unknown)
                    .await
            );
            assert_eq!(service.server_count(), 0);
            *resolver.0.lock().unwrap() = CredentialValidity::unbounded();
            if source_first {
                supervisor
                    .apply_credential_change(&CredentialChangeScope::Unknown)
                    .await;
                assert_eq!(service.server_count(), 0);
                supervisor
                    .apply_candidate(central_test_config(1))
                    .await
                    .unwrap();
            } else {
                assert!(
                    supervisor
                        .apply_credential_change(&CredentialChangeScope::Unknown)
                        .await
                );
            }
            assert_eq!(service.server_count(), 1);
            assert!(health.snapshot().is_readiness_serving());
            supervisor
                .materialization_coordinator
                .expire_material(
                    crate::runtime::MaterialExpiry::Credentials,
                    original,
                    &service,
                    &health,
                )
                .await
                .unwrap();
            assert_eq!(service.server_count(), 1);
            cancellation.cancel();
            monitor.await.unwrap();
        }
    }

    #[tokio::test]
    async fn older_filter_completion_cannot_replace_a_newer_source() {
        for with_resolver in [false, true] {
            for reject_old in [false, true] {
                let datastore = Arc::new(ScriptedDatastore::new(
                    DatastoreRuntimePolicy::new(
                        InitialLoadPolicy::FailFast,
                        ChangeNotificationMode::None,
                    ),
                    [],
                    [],
                ));
                let (mut supervisor, health, service) = supervisor(datastore, Duration::ZERO);
                if with_resolver {
                    supervisor = supervisor.with_credential_resolver(Arc::new(CountingResolver {
                        resolved_servers: Mutex::new(Vec::new()),
                    }));
                }
                let filter = Arc::new(ReorderedFilter {
                    entered: tokio::sync::Notify::new(),
                    release: tokio::sync::Notify::new(),
                    reject_old,
                });
                supervisor.config_filter = filter.clone();
                let older = supervisor.apply_candidate(test_config(1));
                tokio::pin!(older);
                tokio::select! {
                    result = &mut older => panic!("old filter must pause: {result:?}"),
                    () = filter.entered.notified() => {},
                }
                assert_eq!(
                    supervisor.apply_candidate(test_config(2)).await.unwrap(),
                    PublicationOutcome::Published
                );
                let applied = health.snapshot();
                filter.release.notify_one();
                assert_eq!(older.await.unwrap(), PublicationOutcome::Superseded);
                assert_eq!(service.server_count(), 2);
                assert_eq!(health.snapshot(), applied);
            }
        }
    }

    #[tokio::test]
    async fn late_publication_return_cannot_clear_a_rejected_source_observation() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let release = service.pause_next_publication();
        let publication = supervisor.apply_candidate(test_config(1));
        tokio::pin!(publication);
        tokio::select! {
            result = &mut publication => panic!("publication must pause: {result:?}"),
            result = timeout(Duration::from_secs(1), async {
                while service.server_count() != 1 { tokio::task::yield_now().await; }
            }) => result.unwrap(),
        }
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
        supervisor
            .materialization_coordinator
            .reject_observation(&health)
            .await;
        let rejected = health.snapshot();
        release.notify_one();
        assert_eq!(publication.await.unwrap(), PublicationOutcome::Superseded);
        assert_eq!(health.snapshot(), rejected);
        assert_eq!(service.server_count(), 1);
    }

    #[tokio::test]
    async fn credential_refresh_during_source_outage_does_not_claim_source_recovery() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, _) = supervisor(datastore, Duration::ZERO);
        let supervisor = supervisor.with_credential_resolver(Arc::new(CountingResolver {
            resolved_servers: Mutex::new(Vec::new()),
        }));
        supervisor
            .apply_candidate(central_test_config(1))
            .await
            .unwrap();
        let baseline = health.snapshot().materialization_revision().unwrap();
        supervisor
            .materialization_coordinator
            .source_unavailable(&health, true)
            .await;
        assert!(
            supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        let rotated = health.snapshot();
        assert_eq!(rotated.materialization_revision().unwrap().source(), baseline.source());
        assert!(
            rotated
                .materialization_revision()
                .unwrap()
                .credentials()
                .value()
                > baseline.credentials().value()
        );
        assert_eq!(rotated.datastore(), DatastoreState::Stale);
        assert!(rotated
            .degradation_reasons()
            .contains(&DegradationReason::ChangeNotificationsUnavailable));
        assert!(rotated
            .degradation_reasons()
            .contains(&DegradationReason::DatastoreStale));
    }

    #[tokio::test(start_paused = true)]
    async fn failed_source_then_stale_credential_publish_keeps_original_expiry_deadline() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let resolver = Arc::new(SelectiveResolver {
            rejected_server: Mutex::new(None),
        });
        let supervisor = supervisor.with_credential_resolver(resolver.clone());
        let policy = tacacsrs_config::policy::parse_runtime_policy(
            br#"{"tacacsrs:runtime-policy":{"source-stale-timeout-seconds":2}}"#,
        )
        .unwrap();
        service.apply_policy_candidate(Some(&policy)).await.unwrap();
        supervisor
            .apply_candidate(central_test_config(1))
            .await
            .unwrap();
        let original_recovery = health.snapshot().source_recovery_revision().unwrap();

        let cancellation = CancellationToken::new();
        let monitor = supervisor.run_source_expiry(&cancellation);
        tokio::pin!(monitor);
        assert!(futures_util::poll!(&mut monitor).is_pending());

        *resolver.rejected_server.lock().unwrap() = Some("server-1".to_owned());
        assert!(supervisor
            .apply_candidate(central_test_config(2))
            .await
            .is_err());
        assert!(futures_util::poll!(&mut monitor).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;

        supervisor
            .materialization_coordinator
            .source_unavailable(&health, true)
            .await;
        *resolver.rejected_server.lock().unwrap() = None;
        assert!(
            supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        assert_eq!(service.server_count(), 2);
        assert_eq!(health.snapshot().datastore(), DatastoreState::Stale);
        assert_eq!(health.snapshot().source_recovery_revision(), Some(original_recovery));
        assert!(
            health
                .snapshot()
                .materialization_revision()
                .unwrap()
                .source()
                .value()
                > original_recovery.value()
        );
        assert!(futures_util::poll!(&mut monitor).is_pending());

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut monitor).is_pending());
        assert_eq!(
            service.server_count(),
            0,
            "a stale credential publication must not renew the source budget"
        );
        cancellation.cancel();
        monitor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stale_source_expiry_does_not_renew_and_valid_source_recovers() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let policy =
            |seconds| {
                tacacsrs_config::policy::parse_runtime_policy(format!(
            r#"{{"tacacsrs:runtime-policy":{{"source-stale-timeout-seconds":{seconds}}}}}"#
        ).as_bytes()).unwrap()
            };
        service
            .apply_policy_candidate(Some(&policy(2)))
            .await
            .unwrap();
        supervisor.apply_candidate(test_config(1)).await.unwrap();
        let original = health.snapshot().materialization_revision().unwrap();
        assert!(health.set_listener(crate::RuntimeService::ClientApi, crate::ListenerState::Bound));
        assert!(health.snapshot().is_readiness_serving());
        supervisor
            .materialization_coordinator
            .source_unavailable(&health, true)
            .await;
        let cancellation = CancellationToken::new();
        let monitor = supervisor.run_source_expiry(&cancellation);
        tokio::pin!(monitor);
        assert!(futures_util::poll!(&mut monitor).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        service
            .apply_policy_candidate(Some(&policy(100)))
            .await
            .unwrap();
        supervisor
            .materialization_coordinator
            .source_unavailable(&health, true)
            .await;
        assert!(
            supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        assert!(futures_util::poll!(&mut monitor).is_pending());
        assert_eq!(service.server_count(), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut monitor).is_pending());
        assert_eq!(service.server_count(), 0);
        let expired = health.snapshot();
        assert!(expired
            .degradation_reasons()
            .contains(&DegradationReason::SourceExpired));
        assert!(expired.materialization_revision().is_none());
        assert!(expired.has_applied_configuration());
        assert!(!expired.is_readiness_serving());
        assert!(expired.is_liveness_serving());
        assert!(expired.is_startup_serving());
        assert!(
            supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        assert_eq!(
            service.server_count(),
            0,
            "credential refresh cannot revive expired source configuration"
        );
        supervisor.apply_candidate(test_config(2)).await.unwrap();
        assert_eq!(service.server_count(), 2);
        let recovered = health.snapshot();
        assert_eq!(recovered.datastore(), DatastoreState::Current);
        assert!(recovered.is_readiness_serving());
        assert!(!recovered
            .degradation_reasons()
            .contains(&DegradationReason::SourceExpired));
        assert!(
            recovered
                .materialization_revision()
                .unwrap()
                .source()
                .value()
                > original.source().value()
        );
        supervisor
            .materialization_coordinator
            .expire_source(original, &service, &health)
            .await
            .unwrap();
        assert_eq!(
            health.snapshot(),
            recovered,
            "stale expiry must not withdraw a recovered generation"
        );
        cancellation.cancel();
        monitor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn recovered_source_resets_expiry_even_when_health_updates_coalesce() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let policy = tacacsrs_config::policy::parse_runtime_policy(
            br#"{"tacacsrs:runtime-policy":{"source-stale-timeout-seconds":2}}"#,
        )
        .unwrap();
        service.apply_policy_candidate(Some(&policy)).await.unwrap();
        supervisor.apply_candidate(test_config(1)).await.unwrap();
        let first_recovery = health.snapshot().source_recovery_revision().unwrap();
        supervisor
            .materialization_coordinator
            .source_unavailable(&health, true)
            .await;
        let cancellation = CancellationToken::new();
        let monitor = supervisor.run_source_expiry(&cancellation);
        tokio::pin!(monitor);
        assert!(futures_util::poll!(&mut monitor).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        supervisor.apply_candidate(test_config(2)).await.unwrap();
        assert!(
            health
                .snapshot()
                .source_recovery_revision()
                .unwrap()
                .value()
                > first_recovery.value()
        );
        supervisor
            .materialization_coordinator
            .source_unavailable(&health, true)
            .await;
        assert!(futures_util::poll!(&mut monitor).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut monitor).is_pending());
        assert_eq!(service.server_count(), 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut monitor).is_pending());
        assert_eq!(service.server_count(), 0);
        cancellation.cancel();
        monitor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn credential_expiry_does_not_renew_and_revalidation_recovers() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let resolver = Arc::new(SelectiveResolver {
            rejected_server: Mutex::new(None),
        });
        let supervisor = supervisor.with_credential_resolver(resolver.clone());
        let policy = |seconds| {
            tacacsrs_config::policy::parse_runtime_policy(format!(
            r#"{{"tacacsrs:runtime-policy":{{"credential-stale-timeout-seconds":{seconds}}}}}"#).as_bytes()).unwrap()
        };
        service
            .apply_policy_candidate(Some(&policy(2)))
            .await
            .unwrap();
        supervisor
            .apply_candidate(central_test_config(1))
            .await
            .unwrap();
        let original = health.snapshot().materialization_revision().unwrap();
        assert!(health.set_listener(crate::RuntimeService::ClientApi, crate::ListenerState::Bound));
        *resolver.rejected_server.lock().unwrap() = Some("server-0".to_owned());
        assert!(
            !supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        let cancellation = CancellationToken::new();
        let monitor = supervisor.run_credential_expiry(&cancellation);
        tokio::pin!(monitor);
        assert!(futures_util::poll!(&mut monitor).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        service
            .apply_policy_candidate(Some(&policy(100)))
            .await
            .unwrap();
        assert!(
            !supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        assert!(futures_util::poll!(&mut monitor).is_pending());
        assert_eq!(service.server_count(), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut monitor).is_pending());
        assert_eq!(service.server_count(), 0);
        let expired = health.snapshot();
        assert_eq!(expired.datastore(), DatastoreState::Current);
        assert!(expired
            .degradation_reasons()
            .contains(&DegradationReason::CredentialsExpired));
        assert!(!expired
            .degradation_reasons()
            .contains(&DegradationReason::SourceExpired));
        assert!(!expired.is_readiness_serving());
        assert!(expired.is_liveness_serving());
        *resolver.rejected_server.lock().unwrap() = None;
        assert!(
            supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        let recovered = health.snapshot();
        assert!(recovered.is_readiness_serving());
        assert_eq!(recovered.materialization_revision().unwrap().source(), original.source());
        assert!(
            recovered
                .materialization_revision()
                .unwrap()
                .credentials()
                .value()
                > original.credentials().value()
        );
        assert!(!recovered
            .degradation_reasons()
            .contains(&DegradationReason::CredentialsExpired));
        supervisor
            .materialization_coordinator
            .expire_material(
                crate::runtime::MaterialExpiry::Credentials,
                original,
                &service,
                &health,
            )
            .await
            .unwrap();
        assert_eq!(health.snapshot(), recovered);
        cancellation.cancel();
        monitor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn pending_credential_resolution_expires_and_its_late_result_is_superseded() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let resolver = Arc::new(PausingRefreshResolver {
            paused: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
        });
        let supervisor = supervisor.with_credential_resolver(resolver.clone());
        let policy = tacacsrs_config::policy::parse_runtime_policy(
            br#"{"tacacsrs:runtime-policy":{"credential-stale-timeout-seconds":2}}"#,
        )
        .unwrap();
        service.apply_policy_candidate(Some(&policy)).await.unwrap();
        supervisor
            .apply_candidate(central_test_config(1))
            .await
            .unwrap();
        resolver.paused.store(true, Ordering::Release);
        let refresh = supervisor.apply_credential_change(&CredentialChangeScope::Unknown);
        tokio::pin!(refresh);
        assert!(futures_util::poll!(&mut refresh).is_pending());
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CredentialsStale));
        let cancellation = CancellationToken::new();
        let monitor = supervisor.run_credential_expiry(&cancellation);
        tokio::pin!(monitor);
        assert!(futures_util::poll!(&mut monitor).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(futures_util::poll!(&mut monitor).is_pending());
        assert_eq!(service.server_count(), 0);
        resolver.release.notify_one();
        assert!(refresh.await);
        assert_eq!(
            service.server_count(),
            0,
            "pre-expiry resolution must not revive withdrawn material"
        );
        resolver.paused.store(false, Ordering::Release);
        assert!(
            supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        assert_eq!(service.server_count(), 1);
        cancellation.cancel();
        monitor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn recovered_notifications_and_revalidation_clear_credential_staleness() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, _) = supervisor(datastore, Duration::from_secs(1));
        let supervisor = supervisor
            .with_credential_resolver(Arc::new(CountingResolver {
                resolved_servers: Mutex::new(Vec::new()),
            }))
            .with_credential_changes(Arc::new(ScriptedCredentialChangeSource {
                subscriptions: Mutex::new(VecDeque::from([
                    CredentialSubscriptionStep::Error,
                    CredentialSubscriptionStep::Events(vec![CredentialChangeEvent::Recovered]),
                ])),
            }));
        supervisor
            .apply_candidate(central_test_config(1))
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let observing = supervisor.run_credential_notifications(&cancellation);
        tokio::pin!(observing);
        assert!(futures_util::poll!(&mut observing).is_pending());
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CredentialNotificationsUnavailable));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut observing).is_pending());
        let recovered = health.snapshot();
        assert!(!recovered
            .degradation_reasons()
            .contains(&DegradationReason::CredentialNotificationsUnavailable));
        assert!(
            !recovered
                .degradation_reasons()
                .contains(&DegradationReason::CredentialsStale),
            "successful reconnect and validation must clear staleness"
        );
        cancellation.cancel();
        observing.await;
    }

    #[tokio::test(start_paused = true)]
    async fn credential_observation_loss_expires_only_referenced_material() {
        for referenced in [false, true] {
            let datastore = Arc::new(ScriptedDatastore::new(
                DatastoreRuntimePolicy::new(
                    InitialLoadPolicy::FailFast,
                    ChangeNotificationMode::None,
                ),
                [],
                [],
            ));
            let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
            let supervisor = supervisor.with_credential_resolver(Arc::new(CountingResolver {
                resolved_servers: Mutex::new(Vec::new()),
            }));
            let policy = tacacsrs_config::policy::parse_runtime_policy(
                br#"{"tacacsrs:runtime-policy":{"credential-stale-timeout-seconds":1}}"#,
            )
            .unwrap();
            service.apply_policy_candidate(Some(&policy)).await.unwrap();
            supervisor
                .apply_candidate(if referenced {
                    central_test_config(1)
                } else {
                    test_config(1)
                })
                .await
                .unwrap();
            supervisor
                .materialization_coordinator
                .credentials_unavailable(&health)
                .await;
            let cancellation = CancellationToken::new();
            let monitor = supervisor.run_credential_expiry(&cancellation);
            tokio::pin!(monitor);
            assert!(futures_util::poll!(&mut monitor).is_pending());
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(futures_util::poll!(&mut monitor).is_pending());
            assert_eq!(service.server_count(), usize::from(!referenced));
            assert_eq!(
                health
                    .snapshot()
                    .degradation_reasons()
                    .contains(&DegradationReason::CredentialsExpired),
                referenced
            );
            cancellation.cancel();
            monitor.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn independent_expiry_budgets_remain_active_after_the_first_withdrawal() {
        for (source_timeout, credential_timeout) in [(1, 2), (2, 1)] {
            let datastore = Arc::new(ScriptedDatastore::new(
                DatastoreRuntimePolicy::new(
                    InitialLoadPolicy::FailFast,
                    ChangeNotificationMode::None,
                ),
                [],
                [],
            ));
            let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
            let resolver = Arc::new(SelectiveResolver {
                rejected_server: Mutex::new(None),
            });
            let supervisor = supervisor.with_credential_resolver(resolver.clone());
            let policy = tacacsrs_config::policy::parse_runtime_policy(format!(r#"{{"tacacsrs:runtime-policy":{{"credential-stale-timeout-seconds":{credential_timeout},"source-stale-timeout-seconds":{source_timeout}}}}}"#).as_bytes()).unwrap();
            service.apply_policy_candidate(Some(&policy)).await.unwrap();
            supervisor
                .apply_candidate(central_test_config(1))
                .await
                .unwrap();
            *resolver.rejected_server.lock().unwrap() = Some("server-0".to_owned());
            assert!(
                !supervisor
                    .apply_credential_change(&CredentialChangeScope::Unknown)
                    .await
            );
            supervisor
                .materialization_coordinator
                .source_unavailable(&health, true)
                .await;
            let cancellation = CancellationToken::new();
            let source = supervisor.run_source_expiry(&cancellation);
            let credentials = supervisor.run_credential_expiry(&cancellation);
            tokio::pin!(source, credentials);
            assert!(futures_util::poll!(&mut source).is_pending());
            assert!(futures_util::poll!(&mut credentials).is_pending());
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(futures_util::poll!(&mut credentials).is_pending());
            assert!(futures_util::poll!(&mut source).is_pending());
            assert_eq!(service.server_count(), 0);
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(futures_util::poll!(&mut source).is_pending());
            assert!(futures_util::poll!(&mut credentials).is_pending());
            assert!(health
                .snapshot()
                .degradation_reasons()
                .contains(&DegradationReason::SourceExpired));
            *resolver.rejected_server.lock().unwrap() = None;
            assert!(
                supervisor
                    .apply_credential_change(&CredentialChangeScope::Unknown)
                    .await
            );
            assert_eq!(
                service.server_count(),
                0,
                "credential recovery must not bypass expired source configuration"
            );
            supervisor
                .apply_candidate(central_test_config(1))
                .await
                .unwrap();
            assert_eq!(service.server_count(), 1);
            assert!(!health
                .snapshot()
                .degradation_reasons()
                .contains(&DegradationReason::CredentialsExpired));
            cancellation.cancel();
            source.await.unwrap();
            credentials.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_credentials_expire_even_while_source_is_current() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(1)],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        let resolver = Arc::new(SelectiveResolver {
            rejected_server: Mutex::new(None),
        });
        let mut supervisor = supervisor.with_credential_resolver(resolver.clone());
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        *resolver.rejected_server.lock().unwrap() = Some("server-0".to_owned());
        assert!(
            !supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
        let cancellation = CancellationToken::new();
        let running = supervisor.run_until(cancellation.cancelled());
        tokio::pin!(running);
        let expired = tokio::select! {
            result = &mut running => panic!("supervision must remain active: {result:?}"),
            result = timeout(Duration::from_secs(301), async {
                let mut updates = health.subscribe();
                loop {
                    if updates.borrow_and_update().eligible_server_count() == 0 { break; }
                    updates.changed().await.unwrap();
                }
            }) => result,
        };
        cancellation.cancel();
        running.await.unwrap();
        assert!(expired.is_ok(), "failed credentials must not remain usable indefinitely");
        assert_eq!(service.server_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn unavailable_source_does_not_serve_past_the_default_stale_budget() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::Config(1)],
            [],
        ));
        let (mut supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        supervisor
            .materialization_coordinator
            .source_unavailable(&health, true)
            .await;
        let cancellation = CancellationToken::new();
        let running = supervisor.run_until(cancellation.cancelled());
        tokio::pin!(running);
        let expired = tokio::select! {
            result = &mut running => panic!("supervisor must remain active: {result:?}"),
            result = timeout(Duration::from_secs(301), async {
                let mut changes = health.subscribe();
                loop {
                    if changes.borrow_and_update().eligible_server_count() == 0 { break; }
                    changes.changed().await.unwrap();
                }
            }) => result,
        };
        cancellation.cancel();
        running.await.unwrap();
        assert!(expired.is_ok(), "stale source must withdraw its applied upstreams");
        assert_eq!(service.server_count(), 0);
    }

    #[tokio::test]
    async fn source_without_a_resolver_rejects_central_references_before_publication() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (supervisor, health, service) = supervisor(datastore, Duration::ZERO);
        assert!(supervisor
            .apply_candidate(central_test_config(1))
            .await
            .is_err());
        assert_eq!(service.server_count(), 0);
        let rejected = health.snapshot();
        assert!(rejected.materialization_revision().is_none());
        assert!(!rejected.has_applied_configuration());
        assert_eq!(rejected.datastore(), DatastoreState::Unavailable);
        assert!(rejected
            .degradation_reasons()
            .contains(&DegradationReason::CandidateConfigurationRejected));
        supervisor.apply_candidate(test_config(1)).await.unwrap();
        let applied = health.snapshot();
        assert_eq!(applied.materialization_revision().unwrap().source().value(), 2);
        assert_eq!(applied.datastore(), DatastoreState::Current);
        assert!(!applied
            .degradation_reasons()
            .contains(&DegradationReason::CandidateConfigurationRejected));
    }

    #[tokio::test]
    async fn dropped_initialization_reopens_observation_before_retry() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::FailFast,
                ChangeNotificationMode::Continuous,
            ),
            [LoadStep::Config(1), LoadStep::Config(2)],
            [],
        ));
        let (mut supervisor, _, service) = supervisor(datastore.clone(), Duration::ZERO);
        let filter = Arc::new(PausingFilter {
            paused: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            cancelled: Arc::new(AtomicUsize::new(0)),
        });
        supervisor.config_filter = filter.clone();
        {
            let initialize = supervisor.initialize_until(std::future::pending());
            tokio::pin!(initialize);
            tokio::select! {
                result = &mut initialize => panic!("initialization must pause: {result:?}"),
                () = filter.entered.notified() => {}
            }
        }
        timeout(Duration::from_secs(1), supervisor.initialize_until(std::future::pending()))
            .await
            .expect("retry must not await an event from a consumed baseline")
            .unwrap();
        assert_eq!(datastore.subscribe_count.load(Ordering::Relaxed), 2);
        assert_eq!(service.server_count(), 2);
    }

    #[tokio::test]
    async fn initialization_and_updates_share_one_observation_until_cancellation() {
        let dummy = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (_, health, service) = supervisor(dummy, Duration::ZERO);
        let (events, receiver) = tokio::sync::mpsc::channel(2);
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source = Arc::new(OwnedSource {
            events: Mutex::new(Some(receiver)),
            dropped: dropped.clone(),
            opens: AtomicUsize::new(0),
        });
        let change = |count| {
            ConfigChangeEvent::Changed(tacacsrs_config::source::ConfigChange {
                config: Arc::new(test_config(count)),
                delta: tacacsrs_config::source::ConfigDelta::default(),
            })
        };
        events.send(change(1)).await.unwrap();
        let mut supervisor = ConfigSupervisor::new(
            source.clone(),
            service.clone(),
            health,
            Arc::new(NoopTacacsPlusFilter::default()),
        );
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        events.send(change(2)).await.unwrap();
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let task = tokio::spawn(async move { supervisor.run_until(stop.cancelled()).await });
        timeout(Duration::from_secs(1), async {
            while service.server_count() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancellation.cancel();
        task.await.unwrap().unwrap();
        assert_eq!(source.opens.load(Ordering::Relaxed), 1);
        assert!(dropped.load(Ordering::Acquire));
        assert!(events.is_closed());
    }

    #[tokio::test]
    async fn notification_loop_replaces_pending_source_work_and_cancels_it_on_shutdown() {
        let dummy = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (_, health, service) = supervisor(dummy, Duration::ZERO);
        let (events, receiver) = tokio::sync::mpsc::channel(4);
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source = Arc::new(OwnedSource {
            events: Mutex::new(Some(receiver)),
            dropped: dropped.clone(),
            opens: AtomicUsize::new(0),
        });
        let change = |count| {
            ConfigChangeEvent::Changed(tacacsrs_config::source::ConfigChange {
                config: Arc::new(test_config(count)),
                delta: tacacsrs_config::source::ConfigDelta::default(),
            })
        };
        events.send(change(1)).await.unwrap();
        let mut supervisor = ConfigSupervisor::new(
            source,
            service.clone(),
            health,
            Arc::new(NoopTacacsPlusFilter::default()),
        );
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        let filter = Arc::new(PausingFilter {
            paused: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            cancelled: Arc::new(AtomicUsize::new(0)),
        });
        supervisor.config_filter = filter.clone();
        let supervisor = Arc::new(supervisor);
        let cancellation = CancellationToken::new();
        let task = {
            let supervisor = Arc::clone(&supervisor);
            let cancellation = cancellation.clone();
            tokio::spawn(async move { supervisor.run_notifications(&cancellation).await })
        };

        events.send(change(2)).await.unwrap();
        timeout(Duration::from_secs(1), filter.entered.notified())
            .await
            .expect("the older source must enter filtering");
        events.send(change(3)).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while service.server_count() != 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the latest source must replace pending work");
        assert_eq!(filter.cancelled.load(Ordering::Acquire), 1);

        filter.paused.store(false, Ordering::Release);
        events.send(change(4)).await.unwrap();
        timeout(Duration::from_secs(1), filter.entered.notified())
            .await
            .expect("the final source must enter filtering");
        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("shutdown must cancel pending source work")
            .expect("the notification task must join");
        assert_eq!(filter.cancelled.load(Ordering::Acquire), 2);
        assert_eq!(service.server_count(), 3);
        drop(supervisor);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test(start_paused = true)]
    async fn notification_disconnect_cancels_stalled_resolution_and_expires_original_source() {
        let dummy = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (_, health, service) = supervisor(dummy, Duration::ZERO);
        let policy = tacacsrs_config::policy::parse_runtime_policy(
            br#"{"tacacsrs:runtime-policy":{"source-stale-timeout-seconds":2}}"#,
        )
        .unwrap();
        service.apply_policy_candidate(Some(&policy)).await.unwrap();
        let (events, receiver) = tokio::sync::mpsc::channel(2);
        let source = Arc::new(OwnedSource {
            events: Mutex::new(Some(receiver)),
            dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            opens: AtomicUsize::new(0),
        });
        let change = |count| {
            ConfigChangeEvent::Changed(tacacsrs_config::source::ConfigChange {
                config: Arc::new(central_test_config(count)),
                delta: tacacsrs_config::source::ConfigDelta::default(),
            })
        };
        events.send(change(1)).await.unwrap();
        let resolver = Arc::new(StallingResolver {
            stalled: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            cancelled: Arc::new(AtomicUsize::new(0)),
        });
        let mut supervisor = ConfigSupervisor::new(
            source,
            service.clone(),
            health.clone(),
            Arc::new(NoopTacacsPlusFilter::default()),
        )
        .with_credential_resolver(resolver.clone());
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let notifications = supervisor.run_notifications(&cancellation);
        let expiry = supervisor.run_source_expiry(&cancellation);
        tokio::pin!(notifications, expiry);
        assert!(futures_util::poll!(&mut expiry).is_pending());
        assert_eq!(service.server_count(), 1, "the baseline must publish");

        resolver.stalled.store(true, Ordering::Release);
        events.send(change(2)).await.unwrap();
        assert!(futures_util::poll!(&mut notifications).is_pending());
        assert!(
            futures_util::poll!(std::pin::pin!(resolver.entered.notified())).is_ready(),
            "the candidate resolution must stall"
        );
        drop(events);
        assert!(futures_util::poll!(&mut notifications).is_pending());
        assert_eq!(
            health.snapshot().datastore(),
            DatastoreState::Stale,
            "the disconnect must remain observable"
        );
        assert_eq!(resolver.cancelled.load(Ordering::Acquire), 1);
        assert!(futures_util::poll!(&mut expiry).is_pending());

        tokio::time::advance(Duration::from_millis(1_999)).await;
        assert!(futures_util::poll!(&mut expiry).is_pending());
        assert_eq!(service.server_count(), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(futures_util::poll!(&mut expiry).is_pending());
        assert_eq!(service.server_count(), 0);
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::SourceExpired));

        cancellation.cancel();
        notifications.await;
        expiry.await.expect("expiry supervision must stop");
    }

    #[tokio::test]
    async fn file_change_between_initialization_and_serving_is_reconciled() {
        use tacacsrs_config::input::{CliConfigSource, CliDatastoreInput, CliFileDatastore};

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("agent-observation-{unique}.json"));
        let document = |servers| {
            format!(r#"{{"ietf-system-tacacs-plus:tacacs-plus":{{"server":{servers}}}}}"#)
        };
        tokio::fs::write(&path, document(r#"[{"name":"primary","server-type":"accounting","address":"192.0.2.10","port":49,"shared-secret":"test-secret"}]"#)).await.unwrap();
        let dummy = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (_, health, service) = supervisor(dummy, Duration::ZERO);
        let source = Arc::new(CliFileDatastore::new(
            CliDatastoreInput::new(CliConfigSource::YangFile { path: path.clone() }, "file")
                .with_debounce(Duration::ZERO),
        ));
        let mut supervisor = ConfigSupervisor::new(
            source,
            service.clone(),
            health,
            Arc::new(NoopTacacsPlusFilter::default()),
        );
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        tokio::fs::write(&path, document(r#"[{"name":"primary","server-type":"accounting","address":"192.0.2.10","port":49,"shared-secret":"test-secret"},{"name":"secondary","server-type":"accounting","address":"192.0.2.11","port":49,"shared-secret":"test-secret"}]"#)).await.unwrap();
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let task = tokio::spawn(async move { supervisor.run_until(stop.cancelled()).await });
        timeout(Duration::from_secs(2), async {
            while service.server_count() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("file invalidation must survive initialization");
        cancellation.cancel();
        task.await.unwrap().unwrap();
        tokio::fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn initialized_supervisor_starts_credential_notifications_without_reloading_source() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(1)],
            [],
        ));
        let (supervisor, _, service) = supervisor(datastore.clone(), Duration::ZERO);
        let resolver = Arc::new(CountingResolver {
            resolved_servers: Mutex::new(Vec::new()),
        });
        let source = Arc::new(ScriptedCredentialChangeSource {
            subscriptions: Mutex::new(VecDeque::from([CredentialSubscriptionStep::Events(vec![
                CredentialChangeEvent::Recovered,
            ])])),
        });
        let mut supervisor = supervisor
            .with_credential_resolver(resolver.clone())
            .with_credential_changes(source);
        supervisor
            .initialize_until(std::future::pending())
            .await
            .unwrap();
        assert_eq!(service.server_count(), 1);
        assert_eq!(resolver.resolved_servers.lock().unwrap().len(), 1);
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let task = tokio::spawn(async move { supervisor.run_until(stop.cancelled()).await });
        timeout(Duration::from_secs(1), async {
            while resolver.resolved_servers.lock().unwrap().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("credential recovery must run after fail-fast initialization");
        cancellation.cancel();
        task.await.unwrap().unwrap();
        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn host_cancellation_interrupts_resolution_and_keeps_applied_configuration() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(2)],
            [],
        ));
        let (supervisor, _, service) = supervisor(datastore, Duration::ZERO);
        supervisor.apply_candidate(test_config(1)).await.unwrap();
        let resolver = Arc::new(BlockingResolver {
            entered: tokio::sync::Notify::new(),
        });
        let supervisor = supervisor.with_credential_resolver(resolver.clone());
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let task = tokio::spawn(async move { supervisor.run_until(stop.cancelled()).await });
        timeout(Duration::from_secs(1), resolver.entered.notified())
            .await
            .unwrap();
        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(service.server_count(), 1);
    }

    #[tokio::test]
    async fn credential_notifications_without_a_resolver_are_rejected() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::Config(1)],
            [],
        ));
        let (supervisor, _, _) = supervisor(datastore.clone(), Duration::ZERO);
        let source = Arc::new(ScriptedCredentialChangeSource {
            subscriptions: Mutex::new(VecDeque::new()),
        });
        let mut supervisor = supervisor.with_credential_changes(source);
        assert!(supervisor
            .initialize_until(std::future::pending())
            .await
            .is_err());
        assert!(supervisor.run_until(std::future::pending()).await.is_err());
        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cancellation_interrupts_recovery_reload() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::FailFast,
                ChangeNotificationMode::Continuous,
            ),
            [LoadStep::Config(1), LoadStep::Pending],
            [SubscriptionStep::Empty],
        ));
        let (supervisor, _, service) = supervisor(datastore.clone(), Duration::ZERO);
        let cancellation = CancellationToken::new();
        supervisor.load_initial(&cancellation).await.unwrap();
        let stop = cancellation.clone();
        let mut task = tokio::spawn(async move { supervisor.run_notifications(&stop).await });
        timeout(Duration::from_secs(1), async {
            while datastore.load_count.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("recovery reload must start");
        cancellation.cancel();
        let stopped = timeout(Duration::from_millis(100), &mut task).await;
        if stopped.is_err() {
            task.abort();
            let _ = task.await;
        }
        assert!(stopped.is_ok(), "cancellation must interrupt a blocked recovery reload");
        assert_eq!(service.server_count(), 1);
    }

    #[tokio::test]
    async fn older_publication_completion_cannot_clear_newer_credential_failure() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (_, health, service) = supervisor(datastore.clone(), Duration::ZERO);
        let resolver = Arc::new(SelectiveResolver {
            rejected_server: Mutex::new(None),
        });
        let supervisor = ConfigSupervisor::with_backoff_and_resolver(
            datastore,
            service.clone(),
            health.clone(),
            Arc::new(NoopTacacsPlusFilter::default()),
            Arc::new(FixedBackoff(Duration::ZERO)),
            Some(resolver.clone()),
        );
        let release = service.pause_next_publication();
        let publication = supervisor.apply_candidate(central_test_config(1));
        tokio::pin!(publication);
        tokio::select! {
            result = &mut publication => panic!("publication must pause: {result:?}"),
            result = timeout(Duration::from_secs(1), async {
                while service.server_count() != 1 { tokio::task::yield_now().await; }
            }) => result.unwrap(),
        }
        *resolver.rejected_server.lock().unwrap() = Some("server-0".to_owned());
        assert!(
            !supervisor
                .apply_credential_change(&CredentialChangeScope::Unknown)
                .await
        );
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CredentialResolutionFailed));
        release.notify_one();
        publication.await.unwrap();
        assert!(
            health
                .snapshot()
                .degradation_reasons()
                .contains(&DegradationReason::CredentialResolutionFailed),
            "an older completion must not erase a newer credential failure"
        );
    }

    #[tokio::test]
    async fn resolved_candidate_applies_only_after_every_credential_succeeds() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (_, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let resolver = Arc::new(SelectiveResolver {
            rejected_server: Mutex::new(Some("server-1".to_owned())),
        });
        let supervisor = ConfigSupervisor::with_backoff_and_resolver(
            datastore,
            Arc::clone(&service),
            health.clone(),
            Arc::new(NoopTacacsPlusFilter::default()),
            Arc::new(FixedBackoff(Duration::ZERO)),
            Some(Arc::clone(&resolver) as Arc<dyn CredentialResolver>),
        );

        supervisor
            .apply_candidate(test_config(1))
            .await
            .expect("known-good inline candidate");
        assert_eq!(service.server_count(), 1);

        assert!(supervisor
            .apply_candidate(central_test_config(2))
            .await
            .is_err());
        assert_eq!(service.server_count(), 1);
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CredentialResolutionFailed));

        *resolver.rejected_server.lock().expect("resolver lock") = None;
        supervisor
            .apply_candidate(central_test_config(2))
            .await
            .expect("fully resolved candidate");
        assert_eq!(service.server_count(), 2);
        assert!(!health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CredentialResolutionFailed));
    }

    #[tokio::test]
    async fn initial_credential_unavailability_retries_complete_snapshot_before_apply() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::RetryUntilAvailable,
                ChangeNotificationMode::None,
            ),
            [LoadStep::CentralConfig(1), LoadStep::CentralConfig(1)],
            [],
        ));
        let (_, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let resolver = Arc::new(InitiallyUnavailableResolver {
            failures_remaining: AtomicUsize::new(1),
        });
        let supervisor = ConfigSupervisor::with_backoff_and_resolver(
            Arc::clone(&datastore) as Arc<dyn ConfigDatastore>,
            Arc::clone(&service),
            health.clone(),
            Arc::new(NoopTacacsPlusFilter::default()),
            Arc::new(FixedBackoff(Duration::ZERO)),
            Some(resolver as Arc<dyn CredentialResolver>),
        );

        supervisor
            .load_initial(&CancellationToken::new())
            .await
            .expect("initial resolution eventually succeeds");

        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 2);
        assert_eq!(service.server_count(), 1);
        assert!(health.snapshot().has_applied_configuration());
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
    }

    #[tokio::test]
    async fn known_credential_event_rematerializes_only_affected_server() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(2)],
            [],
        ));
        let (_, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let resolver = Arc::new(CountingResolver {
            resolved_servers: Mutex::new(Vec::new()),
        });
        let change_source = Arc::new(ScriptedCredentialChangeSource {
            subscriptions: Mutex::new(VecDeque::from([CredentialSubscriptionStep::Events(vec![
                CredentialChangeEvent::Recovered,
                CredentialChangeEvent::Changed(CredentialChangeScope::Known {
                    kind: CredentialKind::SymmetricKey,
                    reference: CredentialReference::SymmetricKey("object-0".to_owned()),
                }),
            ])])),
        });
        let supervisor = Arc::new(ConfigSupervisor::with_backoff_and_provider(
            datastore,
            Arc::clone(&service),
            health,
            Arc::new(NoopTacacsPlusFilter::default()),
            Arc::new(FixedBackoff(Duration::ZERO)),
            Some(Arc::clone(&resolver) as Arc<dyn CredentialResolver>),
            Some(change_source),
        ));
        let cancellation = CancellationToken::new();
        let task = {
            let supervisor = Arc::clone(&supervisor);
            let cancellation = cancellation.clone();
            tokio::spawn(async move { supervisor.run(&cancellation).await })
        };

        timeout(Duration::from_secs(2), async {
            loop {
                if resolver
                    .resolved_servers
                    .lock()
                    .expect("resolved servers lock")
                    .len()
                    >= 3
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("credential event rematerialization");
        cancellation.cancel();
        task.await
            .expect("supervisor task")
            .expect("supervisor result");

        assert_eq!(
            *resolver
                .resolved_servers
                .lock()
                .expect("resolved servers lock"),
            ["server-0", "server-1", "server-0", "server-1", "server-0"],
        );
        assert_eq!(service.server_count(), 2);
    }

    #[tokio::test]
    async fn credential_refresh_preserves_rejected_datastore_candidate_state() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [],
            [],
        ));
        let (_, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let resolver = Arc::new(CountingResolver {
            resolved_servers: Mutex::new(Vec::new()),
        });
        let supervisor = ConfigSupervisor::with_backoff_and_resolver(
            datastore,
            service,
            health.clone(),
            Arc::new(NoopTacacsPlusFilter::default()),
            Arc::new(FixedBackoff(Duration::ZERO)),
            Some(resolver as Arc<dyn CredentialResolver>),
        );

        supervisor
            .apply_candidate(central_test_config(1))
            .await
            .expect("apply known-good candidate");
        supervisor
            .materialization_coordinator
            .reject_observation(&health)
            .await;

        assert!(
            supervisor
                .apply_credential_change(&CredentialChangeScope::Known {
                    kind: CredentialKind::SymmetricKey,
                    reference: CredentialReference::SymmetricKey("object-0".to_owned()),
                })
                .await
        );

        let snapshot = health.snapshot();
        assert_eq!(snapshot.datastore(), DatastoreState::Stale);
        assert!(snapshot
            .degradation_reasons()
            .contains(&DegradationReason::DatastoreStale));
        assert!(snapshot
            .degradation_reasons()
            .contains(&DegradationReason::CandidateConfigurationRejected));
        assert!(!snapshot
            .degradation_reasons()
            .contains(&DegradationReason::CredentialResolutionFailed));
    }

    #[tokio::test]
    async fn credential_subscription_failure_sets_distinct_health_reason() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::CentralConfig(1)],
            [],
        ));
        let (_, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let resolver = Arc::new(CountingResolver {
            resolved_servers: Mutex::new(Vec::new()),
        });
        let change_source = Arc::new(ScriptedCredentialChangeSource {
            subscriptions: Mutex::new(VecDeque::from([
                CredentialSubscriptionStep::Error,
                CredentialSubscriptionStep::Events(Vec::new()),
            ])),
        });
        let supervisor = Arc::new(ConfigSupervisor::with_backoff_and_provider(
            datastore,
            service,
            health.clone(),
            Arc::new(NoopTacacsPlusFilter::default()),
            Arc::new(FixedBackoff(Duration::from_millis(25))),
            Some(resolver),
            Some(change_source),
        ));
        let cancellation = CancellationToken::new();
        let task = {
            let supervisor = Arc::clone(&supervisor);
            let cancellation = cancellation.clone();
            tokio::spawn(async move { supervisor.run(&cancellation).await })
        };

        timeout(Duration::from_secs(2), async {
            loop {
                if health
                    .snapshot()
                    .degradation_reasons()
                    .contains(&DegradationReason::CredentialNotificationsUnavailable)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("credential notification degradation");
        cancellation.cancel();
        task.await
            .expect("supervisor task")
            .expect("supervisor result");
        assert!(!health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::ChangeNotificationsUnavailable));
    }

    #[tokio::test]
    async fn fail_fast_returns_after_first_initial_load_failure() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::Error],
            [],
        ));
        let (supervisor, health, _) = supervisor(Arc::clone(&datastore), Duration::ZERO);

        let result = supervisor.load_initial(&CancellationToken::new()).await;

        assert!(result.is_err());
        let public_error = result
            .expect_err("fail-fast must return an error")
            .to_string();
        assert!(!public_error.contains("scripted load failure"));
        assert!(!public_error.contains("test-secret"));
        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 1);
        assert_eq!(health.snapshot().datastore(), DatastoreState::Unavailable);
    }

    #[tokio::test]
    async fn retrying_initial_load_applies_first_available_snapshot() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::RetryUntilAvailable,
                ChangeNotificationMode::None,
            ),
            [LoadStep::Error, LoadStep::Error, LoadStep::Config(1)],
            [],
        ));
        let (supervisor, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);

        supervisor
            .load_initial(&CancellationToken::new())
            .await
            .expect("retry must recover");

        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 3);
        assert_eq!(service.server_count(), 1);
        assert!(health.snapshot().has_applied_configuration());
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
    }

    #[tokio::test]
    async fn cancellation_interrupts_initial_retry_sleep() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::RetryUntilAvailable,
                ChangeNotificationMode::None,
            ),
            [LoadStep::Error],
            [],
        ));
        let (supervisor, _, _) = supervisor(Arc::clone(&datastore), Duration::MAX);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();

        let task = tokio::spawn(async move { supervisor.load_initial(&child).await });
        tokio::task::yield_now().await;
        cancellation.cancel();

        timeout(Duration::from_secs(1), task)
            .await
            .expect("supervisor must stop promptly")
            .expect("task must join")
            .expect("cancellation is successful");
        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn notification_none_never_subscribes() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None),
            [LoadStep::Config(1)],
            [],
        ));
        let (supervisor, _, _) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        supervisor
            .run(&cancellation)
            .await
            .expect("static supervisor must stop");

        assert_eq!(datastore.subscribe_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn ended_observation_reopens_before_reading_recovery_baseline() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::RetryUntilAvailable,
                ChangeNotificationMode::Continuous,
            ),
            [LoadStep::Config(1), LoadStep::Config(2)],
            [SubscriptionStep::Empty, SubscriptionStep::Pending],
        ));
        let (supervisor, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();

        let task = tokio::spawn(async move { supervisor.run(&child).await });
        timeout(Duration::from_secs(1), async {
            while datastore.subscribe_count.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervisor must resubscribe");
        cancellation.cancel();
        task.await
            .expect("task must join")
            .expect("supervisor must stop");

        assert_eq!(service.server_count(), 2);
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
    }

    #[tokio::test]
    async fn rejected_candidate_retains_known_good_configuration() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::FailFast,
                ChangeNotificationMode::Continuous,
            ),
            [LoadStep::Config(1)],
            [SubscriptionStep::RejectedThenPending],
        ));
        let (supervisor, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();

        supervisor
            .load_initial(&cancellation)
            .await
            .expect("initial load");
        let task = tokio::spawn(async move { supervisor.run_notifications(&child).await });
        timeout(Duration::from_secs(1), async {
            while !health
                .snapshot()
                .degradation_reasons()
                .contains(&DegradationReason::CandidateConfigurationRejected)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("rejection must be published");
        cancellation.cancel();
        task.await.expect("task must join");

        assert_eq!(service.server_count(), 1);
        assert_eq!(health.snapshot().datastore(), DatastoreState::Stale);
    }

    #[tokio::test]
    async fn restart_required_retains_known_good_configuration_and_readiness() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::FailFast,
                ChangeNotificationMode::Continuous,
            ),
            [LoadStep::Config(1)],
            [SubscriptionStep::RestartThenPending],
        ));
        let (supervisor, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();

        supervisor
            .load_initial(&cancellation)
            .await
            .expect("initial load");
        assert!(health.set_listener(crate::RuntimeService::ClientApi, crate::ListenerState::Bound,));
        let task = tokio::spawn(async move { supervisor.run_notifications(&child).await });
        timeout(Duration::from_secs(1), async {
            while !health
                .snapshot()
                .degradation_reasons()
                .contains(&DegradationReason::RestartRequired)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("restart requirement must be published");
        cancellation.cancel();
        task.await.expect("task must join");

        assert_eq!(service.server_count(), 1);
        assert!(health.snapshot().is_readiness_serving());
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
    }

    #[tokio::test]
    async fn observation_setup_failure_never_loads_an_unobserved_snapshot() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::RetryUntilAvailable,
                ChangeNotificationMode::Continuous,
            ),
            [LoadStep::Config(1), LoadStep::Config(2)],
            [SubscriptionStep::Error, SubscriptionStep::Pending],
        ));
        let (supervisor, _, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();

        let task = tokio::spawn(async move { supervisor.run(&child).await });
        timeout(Duration::from_secs(1), async {
            while datastore.subscribe_count.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervisor must retry subscription");
        cancellation.cancel();
        task.await
            .expect("task must join")
            .expect("supervisor must stop");

        assert_eq!(service.server_count(), 1);
        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn failed_recovery_baseline_reopens_observation_before_retry() {
        let datastore = Arc::new(ScriptedDatastore::new(
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::RetryUntilAvailable,
                ChangeNotificationMode::Continuous,
            ),
            [LoadStep::Config(1), LoadStep::Error, LoadStep::Config(2)],
            [SubscriptionStep::Empty, SubscriptionStep::Pending],
        ));
        let (supervisor, health, service) = supervisor(Arc::clone(&datastore), Duration::ZERO);
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();

        let task = tokio::spawn(async move { supervisor.run(&child).await });
        timeout(Duration::from_secs(1), async {
            while service.server_count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervisor must recover and resubscribe");
        cancellation.cancel();
        task.await
            .expect("task must join")
            .expect("supervisor must stop");

        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 3);
        assert_eq!(datastore.subscribe_count.load(Ordering::Relaxed), 3);
        assert_eq!(service.server_count(), 2);
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
    }
}
