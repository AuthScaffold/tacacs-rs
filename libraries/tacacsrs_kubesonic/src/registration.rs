//! Optional atomic loopback-row registration, separate from read-only discovery.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::time::Instant;

use tacacsrs_lifecycle::{
    EmptyGroup, HealthCheckResult, HealthGroup, HealthGroupKind, HostedService, ShutdownSignal,
    POLL_INTERVAL,
};

use tacacsrs_config::tacacsrs::LocalServices;

use crate::environment::{Environment, LoopbackSettings, SourceSettings};

const KEY: &str = "TACPLUS_SERVER|127.0.0.1";

/// Health group that must be healthy before the registrar creates the row.
///
/// The group rejects an empty member list, so the host must contribute at
/// least one readiness check when it enables registration.
pub struct RegistrationReadiness;

impl HealthGroupKind for RegistrationReadiness {
    const NAME: &'static str = "kubesonic-registration-readiness";
    const EMPTY: EmptyGroup = EmptyGroup::Reject;
}

/// The latest outcome of the loopback registrar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RegistrationState {
    /// The registrar has not completed a ConfigDB operation.
    Starting = 0,
    /// The loopback row is absent, and the registrar waits for readiness.
    WaitingForReadiness = 1,
    /// The loopback row is present.
    Registered = 2,
    /// The latest ConfigDB operation of the registrar failed.
    Unavailable = 3,
}

/// Shares the latest [`RegistrationState`] with health checks.
///
/// The registrar writes the state after each ConfigDB operation. A reader gets
/// the state without I/O.
#[derive(Debug, Default)]
pub struct RegistrationStatus(AtomicU8);

impl RegistrationStatus {
    /// Returns the latest state.
    #[must_use]
    pub fn state(&self) -> RegistrationState {
        match self.0.load(Ordering::Acquire) {
            1 => RegistrationState::WaitingForReadiness,
            2 => RegistrationState::Registered,
            3 => RegistrationState::Unavailable,
            _ => RegistrationState::Starting,
        }
    }

    fn set(&self, state: RegistrationState) {
        self.0.store(state as u8, Ordering::Release);
    }

    /// Returns the secret-free health result of the latest state.
    ///
    /// A registered row is healthy. A registrar that starts or waits for
    /// readiness is degraded. A ConfigDB failure is unhealthy.
    #[must_use]
    pub fn health(&self) -> HealthCheckResult {
        match self.state() {
            RegistrationState::Starting => HealthCheckResult::degraded()
                .with_description("The registrar has not completed a ConfigDB operation."),
            RegistrationState::WaitingForReadiness => HealthCheckResult::degraded()
                .with_description("The registrar waits for readiness before it adds the row."),
            RegistrationState::Registered => {
                HealthCheckResult::healthy().with_description("The loopback row is present.")
            }
            RegistrationState::Unavailable => HealthCheckResult::unhealthy()
                .with_description("The latest ConfigDB operation of the registrar failed."),
        }
    }
}

/// Validated inputs for the optional loopback registrar.
#[derive(Clone, Debug)]
pub struct RegistrarSettings {
    /// ConfigDB connection settings.
    pub source: SourceSettings,
    /// Priority of the registered row.
    pub priority: u16,
    /// Port of the local TACACS+ proxy.
    pub port: u16,
    /// Delay between two repair attempts with unchanged readiness.
    pub retry_interval: Duration,
}

/// Returns registrar settings when registration is enabled.
///
/// # Errors
/// Returns an error when registration is enabled with an invalid priority or
/// without an enabled TCP proxy on `127.0.0.1` with a nonzero port.
pub fn registration_settings(input: &Environment) -> anyhow::Result<Option<RegistrarSettings>> {
    if !input.loopback.enabled {
        return Ok(None);
    }
    Ok(Some(RegistrarSettings {
        source: input.source.clone(),
        priority: input.loopback.priority,
        port: registration_port(&input.loopback, &input.local_services)?,
        retry_interval: input.loopback.retry_interval,
    }))
}

/// Validates enabled registration inputs and returns the proxy port.
pub(crate) fn registration_port(
    loopback: &LoopbackSettings,
    services: &LocalServices,
) -> anyhow::Result<u16> {
    anyhow::ensure!(
        (1..=64).contains(&loopback.priority),
        "TACACSD_LOOPBACK_PRIORITY must be in 1..=64"
    );
    let endpoint = services
        .tacacs_proxy_endpoint
        .as_deref()
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .filter(|endpoint| {
            services.tacacs_proxy_enabled
                && endpoint.ip() == Ipv4Addr::LOCALHOST
                && endpoint.port() != 0
        })
        .context(
            "Loopback registration requires an enabled TCP proxy on 127.0.0.1 with a nonzero port",
        )?;
    Ok(endpoint.port())
}

/// Hosted service that owns the optional loopback row.
///
/// Construction is inert. The service removes a stale row once, then creates
/// the row after [`RegistrationReadiness`] becomes healthy. At shutdown, it
/// removes only the row that it created. It writes each outcome to its
/// [`RegistrationStatus`].
pub struct LoopbackRegistrar {
    settings: RegistrarSettings,
    readiness: HealthGroup<RegistrationReadiness>,
    status: Arc<RegistrationStatus>,
}

impl LoopbackRegistrar {
    /// Diagnostic name of the registrar.
    pub const NAME: &'static str = "Loopback registration";

    /// Creates an inert registrar.
    #[must_use]
    pub fn new(
        settings: RegistrarSettings,
        readiness: HealthGroup<RegistrationReadiness>,
        status: Arc<RegistrationStatus>,
    ) -> Self {
        Self {
            settings,
            readiness,
            status,
        }
    }
}

#[async_trait::async_trait]
impl HostedService for LoopbackRegistrar {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        let settings = &self.settings;
        let mut row =
            LoopbackRegistration::new(settings.source.clone(), settings.priority, settings.port);
        let mut initialized = false;
        let mut previous: Option<bool> = None;
        let mut last_attempt: Option<Instant> = None;
        loop {
            let assessment = tokio::select! {
                biased;
                () = shutdown.requested() => break,
                assessment = self.readiness.assess() => assessment,
            };
            let ready = assessment.is_healthy();
            if previous != Some(ready) {
                if !ready {
                    log::info!(
                        "Loopback registration waits for readiness members: {}",
                        assessment.failed.join(", ")
                    );
                }
                previous = Some(ready);
                last_attempt = None;
            }
            let due = last_attempt.is_none_or(|at| at.elapsed() >= settings.retry_interval);
            if due && !shutdown.is_requested() {
                last_attempt = Some(Instant::now());
                let operation = async {
                    if !initialized {
                        row.remove_stale().await?;
                        initialized = true;
                    }
                    if shutdown.is_requested() {
                        return Ok(None);
                    }
                    row.reconcile(ready).await.map(Some)
                };
                match operation.await {
                    Ok(Some(true)) => self.status.set(RegistrationState::Registered),
                    Ok(Some(false)) => self.status.set(RegistrationState::WaitingForReadiness),
                    Ok(None) => {}
                    Err(_) => {
                        self.status.set(RegistrationState::Unavailable);
                        log::warn!("Loopback registration is unavailable; retrying");
                    }
                }
            }
            tokio::select! {
                biased;
                () = shutdown.requested() => break,
                () = tokio::time::sleep(POLL_INTERVAL.min(settings.retry_interval)) => {}
            }
        }
        row.cleanup()
            .await
            .context("Failed to clean up the owned loopback row")
    }
}

/// Owns only a loopback row that this instance successfully created.
pub struct LoopbackRegistration {
    source: SourceSettings,
    priority: u16,
    port: u16,
    owned: bool,
    uncertain: bool,
}

impl LoopbackRegistration {
    /// Creates a writer for an enabled, validated loopback proxy.
    #[must_use]
    pub fn new(source: SourceSettings, priority: u16, port: u16) -> Self {
        Self {
            source,
            priority,
            port,
            owned: false,
            uncertain: false,
        }
    }

    async fn command<T: redis::FromRedisValue>(&self, command: &redis::Cmd) -> anyhow::Result<T> {
        let mut connection = self.source.connect().await?;
        tokio::time::timeout(self.source.command_timeout, command.query_async(&mut connection))
            .await
            .context("Loopback registration command timed out")?
            .context("Loopback registration command failed")
    }

    /// Removes the startup row under the explicitly enabled legacy policy.
    ///
    /// # Errors
    /// Returns an error when ConfigDB cannot complete the deletion.
    pub async fn remove_stale(&self) -> anyhow::Result<()> {
        let removed: u64 = self.command(redis::cmd("DEL").arg(KEY)).await?;
        if removed > 0 {
            log::warn!("Removed startup loopback row under the enabled registration policy");
        }
        Ok(())
    }

    /// Registers or repairs a missing row only after local readiness.
    ///
    /// Returns `true` when the row is present after the operation.
    ///
    /// # Errors
    /// Returns an error when ConfigDB cannot complete the comparison.
    pub async fn reconcile(&mut self, ready: bool) -> anyhow::Result<bool> {
        let exists: bool = self.command(redis::cmd("EXISTS").arg(KEY)).await?;
        if exists {
            anyhow::ensure!(!self.uncertain, "A previous loopback registration outcome is unknown");
            return Ok(true);
        }
        self.owned = false;
        if ready {
            self.uncertain = true;
            self.owned = self
                .command(
                    redis::cmd("EVAL")
                        .arg(REGISTER)
                        .arg(1)
                        .arg(KEY)
                        .arg(self.port)
                        .arg(self.priority),
                )
                .await?;
            self.uncertain = false;
            if self.owned {
                log::info!("Registered ready loopback proxy");
            } else {
                log::warn!("Another writer created the loopback row; preserving it");
            }
        }
        Ok(ready)
    }

    /// Removes an owned row only while its complete contents remain unchanged.
    ///
    /// # Errors
    /// Returns an error when ConfigDB cannot complete cleanup.
    pub async fn cleanup(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.uncertain,
            "Cannot confirm ownership after an uncertain loopback registration"
        );
        if self.owned {
            let removed: bool = self
                .command(
                    redis::cmd("EVAL")
                        .arg(CLEANUP)
                        .arg(1)
                        .arg(KEY)
                        .arg(self.port)
                        .arg(self.priority),
                )
                .await?;
            if !removed {
                log::warn!("Owned loopback row is absent or changed; preserving external state");
            }
            self.owned = false;
        }
        Ok(())
    }
}

const REGISTER: &str = r"
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
redis.call('HSET', KEYS[1], 'tcp_port', ARGV[1], 'priority', ARGV[2])
return 1
";

const CLEANUP: &str = r"
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' then return 0 end
if redis.call('HLEN', KEYS[1]) ~= 2 then return 0 end
if redis.call('HGET', KEYS[1], 'tcp_port') ~= ARGV[1] then return 0 end
if redis.call('HGET', KEYS[1], 'priority') ~= ARGV[2] then return 0 end
return redis.call('DEL', KEYS[1])
";
