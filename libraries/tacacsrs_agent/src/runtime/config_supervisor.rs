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
    materialization_coordinator: Option<Arc<MaterializationCoordinator>>,
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
        self.materialization_coordinator = Some(Arc::new(MaterializationCoordinator::new(
            credential_resolver,
            self.datastore.validation_options(),
        )));
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
            self.credential_change_source.is_none() || self.materialization_coordinator.is_some(),
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
        let materialization_coordinator = credential_resolver.map(|resolver| {
            Arc::new(MaterializationCoordinator::new(resolver, datastore.validation_options()))
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
                    self.mark_current();
                    return Ok(());
                }
                Ok(PublicationOutcome::Superseded) => {}
                Err(()) if policy == InitialLoadPolicy::FailFast => {
                    self.observation.lock().await.take();
                    self.mark_source_problem();
                    anyhow::bail!(
                        "Datastore '{}' did not supply a valid initial configuration",
                        self.datastore.label(),
                    );
                }
                Err(()) => {
                    self.observation.lock().await.take();
                    self.mark_source_problem();
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
        tokio::join!(
            self.run_notifications(cancellation),
            self.run_credential_notifications(cancellation),
        );
        Ok(())
    }

    /// Maintains a continuous notification source after initial load.
    async fn run_notifications(&self, cancellation: &CancellationToken) {
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
                    let result = tokio::select! {
                        biased;
                        () = cancellation.cancelled() => return,
                        result = self.apply_candidate((*change.config).clone()) => result,
                    };
                    match result {
                        Ok(PublicationOutcome::Published) => self.mark_current(),
                        Ok(PublicationOutcome::Superseded) => {}
                        Err(()) => self.mark_candidate_rejected(),
                    }
                    attempt = 0;
                }
                Ok(ConfigChangeEvent::CandidateRejected) => self.mark_candidate_rejected(),
                Ok(ConfigChangeEvent::RestartRequired { required }) => self
                    .health
                    .set_degraded(DegradationReason::RestartRequired, required),
                Err(()) => {
                    self.observation.lock().await.take();
                    self.mark_subscription_unavailable();
                    attempt = attempt.saturating_add(1);
                    if !self.wait_for_retry(attempt, cancellation).await {
                        return;
                    }
                }
            }
        }
    }

    async fn load_and_apply(&self) -> Result<PublicationOutcome, ()> {
        loop {
            match self.next_observation_event().await? {
                ConfigChangeEvent::Changed(change) => {
                    return self.apply_candidate((*change.config).clone()).await
                }
                ConfigChangeEvent::CandidateRejected => return Err(()),
                ConfigChangeEvent::RestartRequired { required } => self
                    .health
                    .set_degraded(DegradationReason::RestartRequired, required),
            }
        }
    }

    async fn next_observation_event(&self) -> Result<ConfigChangeEvent, ()> {
        let mut current = self.observation.lock().await;
        if current.is_none() {
            *current = Some(self.datastore.observe().await.map_err(|_| {
                if self.datastore.runtime_policy().change_notifications
                    == ChangeNotificationMode::Continuous
                {
                    self.mark_subscription_unavailable();
                }
                log::warn!("Datastore '{}' observation could not start", self.datastore.label());
            })?);
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
            log::warn!("Datastore '{}' observation ended", self.datastore.label());
            Err(())
        }
    }

    async fn apply_candidate(&self, candidate: TacacsPlus) -> Result<PublicationOutcome, ()> {
        let desired_source = candidate.clone();
        let filtered = self.config_filter.filter(candidate).await.map_err(|_| {
            log::warn!(
                "Datastore '{}' configuration candidate was rejected by runtime filtering",
                self.datastore.label(),
            );
        })?;
        let apply = match self.materialization_coordinator.as_deref() {
            Some(coordinator) => {
                let attempt = coordinator
                    .accept_source(
                        desired_source,
                        filtered.tacacs_plus,
                        filtered.proxy_downstream_obfuscation,
                    )
                    .await;
                let result = self.materialize_and_publish(coordinator, attempt).await;
                match result {
                    Ok(PublicationOutcome::Published) => self
                        .health
                        .set_degraded(DegradationReason::CredentialResolutionFailed, false),
                    Ok(PublicationOutcome::Superseded) => {}
                    Err(_) => self
                        .health
                        .set_degraded(DegradationReason::CredentialResolutionFailed, true),
                }
                result
            }
            None => self
                .service
                .reload_tacacs_plus_with_proxy_downstream_obfuscation(
                    filtered.tacacs_plus,
                    filtered.proxy_downstream_obfuscation,
                )
                .await
                .map(|()| PublicationOutcome::Published),
        };
        apply.map_err(|_| {
            log::warn!(
                "The daemon failed to prepare or publish the configuration candidate from datastore '{}'",
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
                self.mark_credential_notifications_unavailable();
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
                        self.apply_credential_change(&scope).await;
                        self.health.set_degraded(
                            DegradationReason::CredentialNotificationsUnavailable,
                            false,
                        );
                    }
                    Some(CredentialChangeEvent::Recovered) => {
                        if self
                            .apply_credential_change(&CredentialChangeScope::Unknown)
                            .await
                        {
                            self.health.set_degraded(
                                DegradationReason::CredentialNotificationsUnavailable,
                                false,
                            );
                        }
                    }
                    Some(CredentialChangeEvent::Unavailable) | None => {
                        self.mark_credential_notifications_unavailable();
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
        let Some(coordinator) = self.materialization_coordinator.as_deref() else {
            return true;
        };
        let Some(attempt) = coordinator.credential_change(scope).await else {
            return true;
        };
        let result = self.materialize_and_publish(coordinator, attempt).await;
        match result {
            Ok(PublicationOutcome::Published) => {
                self.health
                    .set_degraded(DegradationReason::CredentialResolutionFailed, false);
                true
            }
            Ok(PublicationOutcome::Superseded) => true,
            Err(_) => {
                self.health
                    .set_degraded(DegradationReason::CredentialResolutionFailed, true);
                false
            }
        }
    }

    async fn materialize_and_publish(
        &self,
        coordinator: &MaterializationCoordinator,
        attempt: crate::runtime::materialization_coordinator::MaterializationAttempt,
    ) -> anyhow::Result<PublicationOutcome> {
        let prepared = match coordinator.materialize(attempt.clone()).await {
            Ok(prepared) => prepared,
            Err(_) if !coordinator.is_current_attempt(&attempt).await => {
                return Ok(PublicationOutcome::Superseded);
            }
            Err(_) => anyhow::bail!("credential materialization failed"),
        };
        coordinator.publish(prepared, &self.service).await
    }

    async fn wait_for_retry(&self, attempt: u32, cancellation: &CancellationToken) -> bool {
        let delay = self.backoff.delay(attempt);
        tokio::select! {
            () = cancellation.cancelled() => false,
            () = tokio::time::sleep(delay) => true,
        }
    }

    fn mark_current(&self) {
        self.health.set_datastore(DatastoreState::Current);
        self.health
            .set_degraded(DegradationReason::DatastoreUnavailable, false);
        self.health
            .set_degraded(DegradationReason::DatastoreStale, false);
        self.health
            .set_degraded(DegradationReason::CandidateConfigurationRejected, false);
    }

    fn mark_source_problem(&self) {
        let has_known_good = self.health.snapshot().has_applied_configuration();
        self.health.set_datastore(if has_known_good {
            DatastoreState::Stale
        } else {
            DatastoreState::Unavailable
        });
        self.health
            .set_degraded(DegradationReason::DatastoreStale, has_known_good);
        self.health
            .set_degraded(DegradationReason::DatastoreUnavailable, !has_known_good);
    }

    fn mark_subscription_unavailable(&self) {
        self.health.set_continuous_notifications_connected(false);
        self.health
            .set_degraded(DegradationReason::ChangeNotificationsUnavailable, true);
        self.mark_source_problem();
    }

    fn mark_credential_notifications_unavailable(&self) {
        self.health
            .set_degraded(DegradationReason::CredentialNotificationsUnavailable, true);
    }

    fn mark_candidate_rejected(&self) {
        self.health
            .set_degraded(DegradationReason::CandidateConfigurationRejected, true);
        self.mark_source_problem();
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
                self.subscribe().await?
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

        async fn subscribe(&self) -> anyhow::Result<ConfigChangeStream> {
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

        fn label(&self) -> &'static str {
            "scripted"
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
            Ok(Box::new(OwnedObservation {
                events: self
                    .events
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one observation owner"),
                dropped: self.dropped.clone(),
            }))
        }

        async fn load(&self) -> anyhow::Result<TacacsPlus> {
            panic!("runtime must use observation");
        }
        async fn subscribe(&self) -> anyhow::Result<ConfigChangeStream> {
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

    struct PausingFilter {
        paused: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
    }

    impl TacacsPlusFilter for PausingFilter {
        fn filter(
            &self,
            candidate: TacacsPlus,
        ) -> futures_util::future::BoxFuture<'_, anyhow::Result<crate::runtime::FilteredTacacsPlus>>
        {
            Box::pin(async move {
                if !self.paused.swap(true, Ordering::AcqRel) {
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
            if self
                .failures_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| count.checked_sub(1))
                .is_ok()
            {
                return Err(ResolutionError::provider(
                    ProviderErrorKind::Unavailable,
                    request.context(),
                ));
            }
            Ok(ResolvedCredential::SymmetricKey(
                tacacsrs_credential_resolution::SymmetricKeyMaterial {
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
        supervisor.mark_current();
        supervisor.mark_candidate_rejected();

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
