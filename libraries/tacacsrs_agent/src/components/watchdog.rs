//! Optional upstream watchdog that probes the TACACS+ servers on a schedule.

use std::sync::Arc;
use std::time::Duration;

use anyhow::ensure;
use dill::component;
use tokio::time::MissedTickBehavior;

use crate::{RuntimeHealth, UpstreamProbe, UpstreamProbeOutcome};
use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_lifecycle::{HostedService, ShutdownSignal};

use crate::host::StartupCheck;

/// Selects the upstream watchdog.
///
/// The watchdog sends one RFC 8907 accounting WATCHDOG record after each new
/// server set and then once in each interval. Readiness stays withdrawn until
/// the first probe result for each new server set. A failed probe withdraws
/// readiness until a later probe succeeds. Thus the host learns upstream health
/// before the first client request.
///
/// Watchdog records go to the accounting servers and count in their endpoint
/// statistics. The watchdog uses normal client API accounting policy. A final
/// reply with any accounting status counts as connectivity success. Admission
/// pressure or cancellation leaves health unchanged. No accounting upstream
/// produces a failed probe.
pub struct UpstreamWatchdogComponent {
    interval: Duration,
}

impl UpstreamWatchdogComponent {
    /// Creates the component with the probe interval.
    ///
    /// # Errors
    /// Returns an error when the interval is zero.
    pub fn new(interval: Duration) -> anyhow::Result<Self> {
        ensure!(!interval.is_zero(), "The upstream watchdog interval must be more than zero");
        ensure!(
            std::time::Instant::now().checked_add(interval).is_some(),
            "The upstream watchdog interval exceeds the clock range"
        );
        Ok(Self { interval })
    }
}

#[async_trait::async_trait]
impl Component for UpstreamWatchdogComponent {
    fn name(&self) -> &'static str {
        UpstreamWatchdog::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.member::<dyn StartupCheck, ArmUpstreamWatchdog, _>(
            <ArmUpstreamWatchdog as dill::Component>::builder(),
        )?;
        composition.hosted_service(UpstreamWatchdog::builder(self.interval))
    }
}

/// Arms the watchdog after the runtime is prepared and before it publishes servers.
///
/// Startup checks run before any listener binds and before the configuration
/// supervisor starts. Thus readiness cannot report serving before the first
/// probe result.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn StartupCheck)]
struct ArmUpstreamWatchdog {
    probe: Arc<UpstreamProbe>,
}

impl Named for ArmUpstreamWatchdog {
    const NAME: &'static str = "Upstream watchdog arming";
}

#[async_trait::async_trait]
impl StartupCheck for ArmUpstreamWatchdog {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn check(&self) -> anyhow::Result<()> {
        self.probe.arm();
        Ok(())
    }
}

/// Maximum wait before a new probe after an inconclusive result.
///
/// An inconclusive probe leaves the readiness state unchanged. A short retry
/// keeps a pending server set from staying not ready for a full interval.
const INCONCLUSIVE_RETRY: Duration = Duration::from_secs(1);

/// Runs the upstream probes in sequence until shutdown.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct UpstreamWatchdog {
    #[component(explicit)]
    interval: Duration,
    probe: Arc<UpstreamProbe>,
    health: Arc<RuntimeHealth>,
}

impl Named for UpstreamWatchdog {
    const NAME: &'static str = "Upstream watchdog";
}

#[async_trait::async_trait]
impl HostedService for UpstreamWatchdog {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        let mut health = self.health.subscribe();
        let mut probed_epoch = None;
        let mut ticks = tokio::time::interval(self.interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = shutdown.requested() => return Ok(()),
                _ = ticks.tick() => {}
                changed = health.changed() => {
                    if changed.is_err() {
                        // The runtime closed its health. Wait for shutdown.
                        shutdown.requested().await;
                        return Ok(());
                    }
                    let epoch = health.borrow_and_update().upstream_watchdog_epoch();
                    if Some(epoch) == probed_epoch {
                        continue;
                    }
                }
            }
            probed_epoch = Some(self.health.snapshot().upstream_watchdog_epoch());
            let outcome = tokio::select! {
                biased;
                () = shutdown.requested() => return Ok(()),
                outcome = self.probe.probe() => outcome,
            };
            if outcome == UpstreamProbeOutcome::Inconclusive {
                ticks.reset_after(self.interval.min(INCONCLUSIVE_RETRY));
            } else {
                ticks.reset();
            }
        }
    }
}
