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
//! Datastore policy determines whether an initial failure is fatal and whether
//! an observation must be continuously restored. Each session supplies a
//! baseline after observation starts. Generation and health publication is
//! atomic: the service reload commits the generation, catalog, and health in one
//! step through the upstream manager publication controller.
//!
//! # Concurrent supervision loops
//!
//! [`ConfigSupervisor`] joins independent owned futures. No loop spawns a
//! detached task, and the host stop future cancels all of them together:
//!
//! - Source observation applies each new candidate and retains the last known
//!   good set on failure.
//! - Provider refresh re-resolves credentials before their prepared lifetime
//!   ends, without waiting for a change notification.
//! - Expiry monitors withdraw the catalog when the source or credentials pass
//!   their stale budget.
//!
//! # Expiry and recovery
//!
//! Each expiry monitor captures a deadline from the first stale or non-empty
//! applied catalog. Repeated failures, credential refreshes, and policy changes
//! do not renew that deadline. A valid new source or credential publication
//! clears the stale state and resets the deadline. Withdrawal publishes an empty
//! catalog with immediate endpoint retirement, but keeps the runtime
//! recoverable.

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


mod expiry;
mod observation;
mod refresh;

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

    async fn wait_for_retry(&self, attempt: u32, cancellation: &CancellationToken) -> bool {
        let delay = self.backoff.delay(attempt);
        tokio::select! {
            () = cancellation.cancelled() => false,
            () = tokio::time::sleep(delay) => true,
        }
    }
}

#[cfg(test)]
mod tests;
