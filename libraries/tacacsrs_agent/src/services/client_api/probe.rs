//! An in-process accounting client that publishes watchdog health.

use std::future::Future;

use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_protocol::failure::{FailureCategory, FailurePhase};
use tacacsrs_protocol::failure::ServiceError;
use tacacsrs_protocol::operations::AccountingOperationResponse;

use crate::RuntimeHealthPublisher;

use super::ClientApiHandle;

/// Result of one upstream WATCHDOG probe.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UpstreamProbeOutcome {
    /// A server returned a WATCHDOG accounting reply with any status.
    ///
    /// An error status still proves the connection, the transport security,
    /// and the shared secret, so it counts as a success.
    Succeeded,
    /// No eligible server returned a WATCHDOG accounting reply.
    Failed,
    /// Admission pressure, cancellation, or a server-set change prevented a result.
    /// The probe did not change runtime health.
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
/// Each tick submits one ordinary accounting operation. Admission, deadlines,
/// routing, recovery, and retry use the client API policy. A result applies
/// only to the server set that was active when the probe started.
#[derive(Clone)]
pub struct UpstreamProbe {
    client: ClientApiHandle,
    health: RuntimeHealthPublisher,
}

impl UpstreamProbe {
    pub(crate) fn new(client: ClientApiHandle, health: RuntimeHealthPublisher) -> Self {
        Self { client, health }
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
    /// No eligible accounting server produces a failed probe.
    pub async fn probe(&self) -> UpstreamProbeOutcome {
        run_probe(self.client.accounting_record(watchdog_request()), &self.health).await
    }
}

async fn run_probe(
    request: impl Future<Output = Result<AccountingOperationResponse, ServiceError>>,
    health: &RuntimeHealthPublisher,
) -> UpstreamProbeOutcome {
    // Read the epoch first. A later server-set change then discards this result.
    let epoch = health.snapshot().upstream_watchdog_epoch();
    let outcome = match request.await {
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
            if error.facts.category() == FailureCategory::Cancelled
                || (error.facts.phase() == FailurePhase::Admission
                    && matches!(
                        error.facts.category(),
                        FailureCategory::Overloaded | FailureCategory::Deadline
                    )) =>
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

fn watchdog_request() -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::WATCHDOG,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNotSet,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: "tacacsrs-agent".to_owned(),
        port: "tacacsrs-agent".to_owned(),
        rem_address: "127.0.0.1".to_owned(),
        args: vec![
            "task_id=tacacsrs-agent-watchdog".to_owned(),
            "service=tacacsrs-agent".to_owned(),
            "watchdog=true".to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType};

    use super::*;
    use crate::config::{
        FailoverStrategy, OperationPolicies, PolicyService, PreparedProxyPolicy, RequestLimits,
        RuntimePolicy,
    };
    use crate::services::client_api::UpstreamBridge;
    use crate::test_support::{FakeConnection, FakeConnector};
    use crate::upstream::{OperationKind, OperationRouter};
    use crate::upstream::manager::{ServiceConnector, UpstreamManager};
    use crate::{DegradationReason, EnabledServices, ListenerState, RuntimeService};

    struct Fixture {
        manager: Arc<UpstreamManager<ServiceConnector>>,
        bridge: UpstreamBridge<ServiceConnector>,
        connector: Arc<FakeConnector>,
        health: RuntimeHealthPublisher,
    }

    impl Fixture {
        fn new(names: &[&str], strategy: FailoverStrategy) -> Self {
            let connector = Arc::new(FakeConnector::new(
                names
                    .iter()
                    .map(|name| {
                        let address = format!("{name}:49");
                        (
                            address.clone(),
                            Arc::new(FakeConnection {
                                address,
                                usable: AtomicBool::new(true),
                                fail_next_request: AtomicBool::new(false),
                            }),
                        )
                    })
                    .collect::<HashMap<_, _>>(),
            ));
            let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
            let limits = RequestLimits::new(1024, 1).unwrap();
            let policy = RuntimePolicy::new(
                strategy,
                FailoverStrategy::default(),
                OperationPolicies::new(limits, limits, limits),
                Duration::from_secs(30),
            )
            .unwrap();
            let manager = Arc::new(
                UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
                    names
                        .iter()
                        .map(|name| {
                            Arc::new(
                                TacacsPlusServerBuilder::new(
                                    *name,
                                    TacacsPlusServerType::all(),
                                    *name,
                                    49,
                                )
                                .build(),
                            )
                        })
                        .collect(),
                    PreparedProxyPolicy::unobfuscated(),
                    policy,
                    connector.clone(),
                    health.clone(),
                    Default::default(),
                )
                .unwrap(),
            );
            health.set_applied_configuration(true);
            health.set_eligible_server_count(names.len());
            health.set_listener(RuntimeService::ClientApi, ListenerState::Bound);
            health.arm_upstream_watchdog();
            Self {
                bridge: UpstreamBridge::new(manager.clone()),
                manager,
                connector,
                health,
            }
        }

        async fn probe(&self) -> UpstreamProbeOutcome {
            run_probe(self.bridge.execute_accounting_record(watchdog_request()), &self.health).await
        }
    }

    #[tokio::test]
    async fn unknown_delivery_stops_each_tick_and_the_next_tick_can_fail_over() {
        for strategy in [
            FailoverStrategy::DeferredFailover,
            FailoverStrategy::OrderedSafeRetry,
        ] {
            let fixture = Fixture::new(&["primary", "backup"], strategy);
            fixture.connector.connections["primary:49"]
                .fail_next_request
                .store(true, Ordering::Relaxed);
            assert_eq!(fixture.probe().await, UpstreamProbeOutcome::Failed);
            assert_eq!(fixture.connector.connect_attempts_for("backup:49").await, 0);
            assert!(!fixture.health.snapshot().is_readiness_serving());
            assert!(fixture.health.snapshot().is_listening());
            assert_eq!(fixture.probe().await, UpstreamProbeOutcome::Succeeded);
            assert!(fixture.health.snapshot().is_readiness_serving());
        }
    }

    #[tokio::test]
    async fn error_reply_uses_the_normal_failover_strategy() {
        for strategy in [
            FailoverStrategy::DeferredFailover,
            FailoverStrategy::OrderedSafeRetry,
        ] {
            let fixture = Fixture::new(&["accounting-error", "backup"], strategy);
            assert_eq!(fixture.probe().await, UpstreamProbeOutcome::Succeeded);
            let expected = usize::from(strategy == FailoverStrategy::OrderedSafeRetry);
            assert_eq!(fixture.connector.connect_attempts_for("backup:49").await, expected);
            assert!(fixture.health.snapshot().is_readiness_serving());
        }
    }

    #[tokio::test]
    async fn intermediate_error_does_not_override_a_later_failed_attempt() {
        let fixture =
            Fixture::new(&["accounting-error", "backup"], FailoverStrategy::OrderedSafeRetry);
        fixture.connector.connections["backup:49"]
            .fail_next_request
            .store(true, Ordering::Relaxed);
        assert_eq!(fixture.probe().await, UpstreamProbeOutcome::Failed);
    }

    #[tokio::test]
    async fn three_servers_use_ordinary_ordered_retry() {
        let fixture = Fixture::new(
            &["accounting-error-a", "accounting-error-b", "healthy"],
            FailoverStrategy::OrderedSafeRetry,
        );
        assert_eq!(fixture.probe().await, UpstreamProbeOutcome::Succeeded);
        assert_eq!(fixture.connector.connect_attempts_for("healthy:49").await, 1);
    }

    #[tokio::test]
    async fn missing_accounting_upstream_fails_instead_of_skipping() {
        let fixture = Fixture::new(&[], FailoverStrategy::default());
        assert_eq!(fixture.probe().await, UpstreamProbeOutcome::Failed);
        assert!(fixture
            .health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::UpstreamWatchdogFailed));
    }

    #[tokio::test(start_paused = true)]
    async fn admission_pressure_is_inconclusive_without_upstream_io() {
        let fixture = Fixture::new(&["primary"], FailoverStrategy::default());
        let routing = OperationRouter::new(fixture.manager.clone(), PolicyService::ClientApi)
            .capture_request(OperationKind::Accounting);
        let _occupied = routing.admit(1).await.unwrap();
        assert_eq!(fixture.probe().await, UpstreamProbeOutcome::Inconclusive);
        assert_eq!(fixture.connector.connect_attempts_for("primary:49").await, 0);
        assert!(fixture
            .health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::UpstreamWatchdogPending));
    }

    #[tokio::test]
    async fn old_probe_cannot_publish_health_for_a_replacement() {
        let fixture = Fixture::new(&["primary"], FailoverStrategy::default());
        let request = async {
            let response = fixture
                .bridge
                .execute_accounting_record(watchdog_request())
                .await;
            fixture
                .manager
                .reload_shared_servers(Vec::new())
                .await
                .unwrap();
            response
        };
        assert_eq!(run_probe(request, &fixture.health).await, UpstreamProbeOutcome::Inconclusive);
        assert!(fixture
            .health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::UpstreamWatchdogPending));
    }
}
