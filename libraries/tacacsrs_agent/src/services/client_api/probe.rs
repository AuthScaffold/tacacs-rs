//! Public upstream probe over the shared upstream manager.

use tacacsrs_networking::routed::EndpointConnector;
use tacacsrs_protocol::failure::{FailureCategory, FailurePhase};

use crate::RuntimeHealthPublisher;
use crate::upstream::{NetworkUpstreamConnector, UpstreamConnection};

use super::upstream_bridge::UpstreamBridge;

/// Result of one upstream WATCHDOG probe.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UpstreamProbeOutcome {
    /// No server is eligible for accounting, so the probe sent nothing.
    ///
    /// This result clears the pending and failed watchdog states of the
    /// current server set, because there is no accounting path to prove.
    Skipped,
    /// A server returned a WATCHDOG accounting reply with any status.
    ///
    /// An error status still proves the connection, the transport security,
    /// and the shared secret, so it counts as a success.
    Succeeded,
    /// No eligible server returned a WATCHDOG accounting reply.
    Failed,
    /// The probe stopped before it reached a server, or the server set changed
    /// during the probe. The probe did not change runtime health.
    Inconclusive,
}

/// Cloneable handle that proves the upstream path with RFC 8907 WATCHDOG records.
///
/// Each probe uses the same server selection, failover, and connection reuse
/// as client API accounting. The probe publishes its result to runtime health.
/// A failed probe adds
/// [`DegradationReason::UpstreamWatchdogFailed`](crate::DegradationReason::UpstreamWatchdogFailed)
/// and withdraws readiness. A successful probe removes this reason.
///
/// The probe skips client admission and tries each eligible accounting server,
/// independent of the failover strategy. A result applies only to the server
/// set that was active when the probe started.
#[derive(Clone)]
pub struct UpstreamProbe {
    bridge: UpstreamBridge<NetworkUpstreamConnector>,
    health: RuntimeHealthPublisher,
}

impl UpstreamProbe {
    pub(crate) fn new(
        bridge: UpstreamBridge<NetworkUpstreamConnector>,
        health: RuntimeHealthPublisher,
    ) -> Self {
        Self { bridge, health }
    }

    /// Withdraws readiness until a probe has a result for the current server set.
    ///
    /// Call this method once before the runtime starts, when a host runs
    /// probes on a schedule. Without a later probe, readiness stays withdrawn.
    pub fn arm(&self) {
        self.health.arm_upstream_watchdog();
    }

    /// Sends one WATCHDOG record and publishes the result to runtime health.
    ///
    /// When no server in the active set is eligible for accounting, the probe
    /// sends nothing and clears an earlier probe failure.
    pub async fn probe(&self) -> UpstreamProbeOutcome {
        run_probe(&self.bridge, &self.health).await
    }
}

/// Sends one probe through `bridge` and publishes the result to `health`.
pub(crate) async fn run_probe<Connector>(
    bridge: &UpstreamBridge<Connector>,
    health: &RuntimeHealthPublisher,
) -> UpstreamProbeOutcome
where
    Connector: EndpointConnector,
    Connector::Connection: UpstreamConnection,
{
    // Read the epoch first. A later server-set change then discards this result.
    let epoch = health.snapshot().upstream_watchdog_epoch();
    if !bridge.has_accounting_server() {
        // Nothing can prove or disprove the upstream path, so clear an old result.
        if !health.set_upstream_watchdog_failed(epoch, false) {
            return UpstreamProbeOutcome::Inconclusive;
        }
        return UpstreamProbeOutcome::Skipped;
    }
    let outcome = match bridge.execute_watchdog_probe().await {
        Ok(response) => {
            // A strict server can reject a WATCHDOG record without a START
            // record. Its reply still proves the whole upstream path.
            log::debug!(
                "Upstream watchdog probe got status {:?} from {}",
                response.status,
                response.server,
            );
            UpstreamProbeOutcome::Succeeded
        }
        Err(error)
            if error.facts.phase() == FailurePhase::Admission
                || error.facts.category() == FailureCategory::Cancelled =>
        {
            log::debug!("Upstream watchdog probe stopped before it reached a server: {error}");
            return UpstreamProbeOutcome::Inconclusive;
        }
        Err(error) => {
            log::warn!("Upstream watchdog probe failed: {error}");
            UpstreamProbeOutcome::Failed
        }
    };
    if health.set_upstream_watchdog_failed(epoch, outcome == UpstreamProbeOutcome::Failed) {
        outcome
    } else {
        log::debug!("Upstream watchdog probe result is for an old server set");
        UpstreamProbeOutcome::Inconclusive
    }
}
