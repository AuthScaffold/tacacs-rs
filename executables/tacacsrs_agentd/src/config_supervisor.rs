//! Cancellable datastore loading and change-subscription supervision.
//!
//! The supervisor owns dependency recovery while the reusable agent runtime
//! owns the applied server set:
//!
//! ```text
//! load candidate -> daemon filter -> atomic service reload -> health current
//!       |                                      |
//!       +-- failure -> retain known good ------+-> health stale/unavailable
//! ```
//!
//! Datastore policy determines whether initial failure is fatal and whether a
//! change stream must be continuously restored. Stream restoration always
//! performs a fresh load before resubscribing so changes missed during an
//! outage cannot be silently skipped.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tacacsrs_agent::{DatastoreState, DegradationReason, RuntimeHealthPublisher, TacacsClientService};
use tacacsrs_config::TacacsPlus;
use tacacsrs_credential_resolution::CredentialResolver;
use tacacsrs_datastore::{
    ChangeNotificationMode, ConfigChangeEvent, ConfigDatastore, InitialLoadPolicy,
};
use tokio_util::sync::CancellationToken;

use crate::config_filter::TacacsPlusFilter;

/// Supplies retry delays without owning asynchronous sleeping.
pub(crate) trait RetryBackoff: Send + Sync {
    /// Returns the delay after a consecutive failure, starting at attempt one.
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
pub(crate) struct ConfigSupervisor {
    datastore: Arc<dyn ConfigDatastore>,
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
    config_filter: Arc<dyn TacacsPlusFilter>,
    backoff: Arc<dyn RetryBackoff>,
    credential_resolver: Option<Arc<dyn CredentialResolver>>,
}

impl ConfigSupervisor {
    /// Creates a supervisor with production retry timing.
    #[must_use]
    pub(crate) fn new(
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

    /// Creates a supervisor that resolves all central credentials before apply.
    #[must_use]
    pub(crate) fn new_with_credential_resolver(
        datastore: Arc<dyn ConfigDatastore>,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
        config_filter: Arc<dyn TacacsPlusFilter>,
        credential_resolver: Arc<dyn CredentialResolver>,
    ) -> Self {
        Self::with_backoff_and_resolver(
            datastore,
            service,
            health,
            config_filter,
            Arc::new(ExponentialBackoff::production()),
            Some(credential_resolver),
        )
    }

    fn with_backoff(
        datastore: Arc<dyn ConfigDatastore>,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
        config_filter: Arc<dyn TacacsPlusFilter>,
        backoff: Arc<dyn RetryBackoff>,
    ) -> Self {
        Self::with_backoff_and_resolver(datastore, service, health, config_filter, backoff, None)
    }

    fn with_backoff_and_resolver(
        datastore: Arc<dyn ConfigDatastore>,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
        config_filter: Arc<dyn TacacsPlusFilter>,
        backoff: Arc<dyn RetryBackoff>,
        credential_resolver: Option<Arc<dyn CredentialResolver>>,
    ) -> Self {
        Self {
            datastore,
            service,
            health,
            config_filter,
            backoff,
            credential_resolver,
        }
    }

    /// Loads and applies the initial snapshot according to datastore policy.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when a fail-fast datastore cannot supply a
    /// valid candidate. Cancellation is a successful shutdown outcome.
    pub(crate) async fn load_initial(
        &self,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<()> {
        let policy = self.datastore.runtime_policy().initial_load;
        let mut attempt = 0u32;

        loop {
            self.health.set_datastore(DatastoreState::Loading);
            let result = tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                result = self.load_and_apply() => result,
            };

            match result {
                Ok(()) => {
                    self.mark_current();
                    return Ok(());
                }
                Err(()) if policy == InitialLoadPolicy::FailFast => {
                    self.mark_source_problem();
                    anyhow::bail!(
                        "Datastore '{}' could not supply a valid initial configuration",
                        self.datastore.label(),
                    );
                }
                Err(()) => {
                    self.mark_source_problem();
                    attempt = attempt.saturating_add(1);
                    log::warn!(
                        "Datastore '{}' initial configuration is unavailable; retrying",
                        self.datastore.label(),
                    );
                    if !self.wait_for_retry(attempt, cancellation).await {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Runs initial loading and then maintains notifications until cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error only when fail-fast initial loading fails.
    pub(crate) async fn run(&self, cancellation: &CancellationToken) -> anyhow::Result<()> {
        self.load_initial(cancellation).await?;
        if cancellation.is_cancelled() {
            return Ok(());
        }
        self.run_notifications(cancellation).await;
        Ok(())
    }

    /// Maintains a continuous notification source after initial load.
    pub(crate) async fn run_notifications(&self, cancellation: &CancellationToken) {
        if self.datastore.runtime_policy().change_notifications == ChangeNotificationMode::None {
            cancellation.cancelled().await;
            return;
        }

        let mut attempt = 0u32;
        let mut refresh_before_subscribe = false;
        loop {
            if refresh_before_subscribe {
                if self.load_and_apply().await.is_ok() {
                    self.mark_current();
                    attempt = 0;
                } else {
                    self.mark_source_problem();
                    attempt = attempt.saturating_add(1);
                    if !self.wait_for_retry(attempt, cancellation).await {
                        return;
                    }
                    continue;
                }
            }

            let subscription = tokio::select! {
                () = cancellation.cancelled() => return,
                result = self.datastore.subscribe() => result,
            };
            let Ok(mut stream) = subscription else {
                log::warn!(
                    "Datastore '{}' change subscription is unavailable",
                    self.datastore.label(),
                );
                self.mark_subscription_unavailable();
                attempt = attempt.saturating_add(1);
                if !self.wait_for_retry(attempt, cancellation).await {
                    return;
                }
                refresh_before_subscribe = true;
                continue;
            };

            self.health.set_continuous_notifications_connected(true);
            self.health
                .set_degraded(DegradationReason::ChangeNotificationsUnavailable, false);
            attempt = 0;
            loop {
                let event = tokio::select! {
                    () = cancellation.cancelled() => return,
                    event = stream.next() => event,
                };
                match event {
                    Some(ConfigChangeEvent::Changed(change)) => {
                        if self.apply_candidate((*change.config).clone()).await.is_ok() {
                            self.mark_current();
                        } else {
                            self.mark_candidate_rejected();
                        }
                    }
                    Some(ConfigChangeEvent::CandidateRejected) => {
                        self.mark_candidate_rejected();
                    }
                    Some(ConfigChangeEvent::RestartRequired { required }) => {
                        self.health
                            .set_degraded(DegradationReason::RestartRequired, required);
                    }
                    None => {
                        log::warn!(
                            "Datastore '{}' continuous change stream ended; reconnecting",
                            self.datastore.label(),
                        );
                        self.mark_subscription_unavailable();
                        refresh_before_subscribe = true;
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

    async fn load_and_apply(&self) -> Result<(), ()> {
        let candidate = self.datastore.load().await.map_err(|_| {
            log::warn!("Datastore '{}' configuration load failed", self.datastore.label());
        })?;
        self.apply_candidate(candidate).await
    }

    async fn apply_candidate(&self, candidate: TacacsPlus) -> Result<(), ()> {
        let filtered = self.config_filter.filter(candidate).await.map_err(|_| {
            log::warn!(
                "Datastore '{}' configuration candidate was rejected by runtime filtering",
                self.datastore.label(),
            );
        })?;
        let apply = match self.credential_resolver.as_deref() {
            Some(resolver) => {
                self.service
                    .resolve_and_reload_tacacs_plus_with_proxy_downstream_obfuscation(
                        filtered.tacacs_plus,
                        filtered.proxy_downstream_obfuscation,
                        resolver,
                    )
                    .await
            }
            None => {
                self.service
                    .reload_tacacs_plus_with_proxy_downstream_obfuscation(
                        filtered.tacacs_plus,
                        filtered.proxy_downstream_obfuscation,
                    )
                    .await
            }
        };
        apply.map_err(|_| {
            log::warn!(
                "Datastore '{}' configuration candidate was rejected by runtime validation",
                self.datastore.label(),
            );
        })
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
    use tacacsrs_agent::{EnabledServices, ProxyDownstreamObfuscation, ServiceConfig};
    use tacacsrs_agent_client::IpcEndpoint;
    use tacacsrs_config::{TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
    use tacacsrs_config::{EpskSupportedHash, Tls13Epsk, TlsClientClientIdentity};
    use tacacsrs_credential_resolution::{
        CredentialRequest, ProviderErrorKind, ResolutionError, ResolvedCredential, SecretBytes,
    };
    use tacacsrs_datastore::{ConfigChangeStream, DatastoreRuntimePolicy};
    use tokio::time::timeout;

    use super::*;
    use crate::config_filter::NoopTacacsPlusFilter;

    #[derive(Debug, Clone, Copy)]
    enum LoadStep {
        Error,
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
            Ok(ResolvedCredential::SymmetricKey(SecretBytes::new(b"resolved-after-retry".to_vec())))
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
            Ok(ResolvedCredential::SymmetricKey(SecretBytes::new(
                b"resolved-supervisor-secret".to_vec(),
            )))
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
            .expect("test config")
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
                    enabled_services: EnabledServices::CLIENT_API,
                    endpoint: IpcEndpoint::default_local(),
                    proxy_endpoint: None,
                    proxy_downstream_obfuscation: ProxyDownstreamObfuscation::default(),
                    tacacs_plus: TacacsPlus::empty(),
                    preferred_probe_interval: Duration::from_secs(1),
                    #[cfg(unix)]
                    socket_mode: 0o660,
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
            health,
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

        *resolver.rejected_server.lock().expect("resolver lock") = None;
        supervisor
            .apply_candidate(central_test_config(2))
            .await
            .expect("fully resolved candidate");
        assert_eq!(service.server_count(), 2);
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
            .expect_err("fail-fast should return an error")
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
            .expect("retry should recover");

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
            .expect("supervisor should stop promptly")
            .expect("task should join")
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
            .expect("static supervisor should stop");

        assert_eq!(datastore.subscribe_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn ended_stream_refreshes_snapshot_before_resubscribing() {
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
        .expect("supervisor should resubscribe");
        cancellation.cancel();
        task.await
            .expect("task should join")
            .expect("supervisor should stop");

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
        .expect("rejection should be published");
        cancellation.cancel();
        task.await.expect("task should join");

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
        assert!(health.set_listener(
            tacacsrs_agent::RuntimeService::ClientApi,
            tacacsrs_agent::ListenerState::Bound,
        ));
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
        .expect("restart requirement should be published");
        cancellation.cancel();
        task.await.expect("task should join");

        assert_eq!(service.server_count(), 1);
        assert!(health.snapshot().is_readiness_serving());
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
    }

    #[tokio::test]
    async fn subscription_setup_failure_refreshes_before_retry() {
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
        .expect("supervisor should retry subscription");
        cancellation.cancel();
        task.await
            .expect("task should join")
            .expect("supervisor should stop");

        assert_eq!(service.server_count(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_after_stream_end_retries_load_before_resubscribing() {
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
            while datastore.subscribe_count.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervisor should recover and resubscribe");
        cancellation.cancel();
        task.await
            .expect("task should join")
            .expect("supervisor should stop");

        assert_eq!(datastore.load_count.load(Ordering::Relaxed), 3);
        assert_eq!(datastore.subscribe_count.load(Ordering::Relaxed), 2);
        assert_eq!(service.server_count(), 2);
        assert_eq!(health.snapshot().datastore(), DatastoreState::Current);
    }
}
