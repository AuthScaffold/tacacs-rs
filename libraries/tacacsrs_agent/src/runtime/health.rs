//! Typed runtime health state and publication.
//!
//! The health model describes the agent without embedding a hosting protocol.
//! It contains no free-form messages or configuration values, so every
//! subscriber receives the same secret-free state.
//!
//! ```text
//! datastore ─┐
//! listeners ─┼─> RuntimeHealthPublisher ─> watch snapshots ─┬─> gRPC health
//! upstreams ─┘                                              ├─> systemd
//!                                                          └─> operator logs
//! ```
//!
//! Runtime owners publish synchronous state transitions. Consumers subscribe
//! through [`tokio::sync::watch`] and translate immutable snapshots into their
//! platform-specific representation. No lock is exposed or held across an
//! await point.

use std::collections::BTreeSet;

use tokio::sync::watch;

use crate::EnabledServices;

/// Process lifecycle state.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RuntimeLifecycle {
    /// Runtime components are being initialized.
    Starting,
    /// All startup conditions have completed and listeners are serving.
    Serving,
    /// Readiness has been withdrawn and listeners are draining active work.
    Draining,
    /// All runtime work has stopped.
    Stopped,
    /// An unrecoverable internal failure requires process termination.
    Failed,
}

/// State of the configured datastore snapshot.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DatastoreState {
    /// No complete validated snapshot has been loaded yet.
    Loading,
    /// The applied snapshot is current with the source.
    Current,
    /// A previous valid snapshot remains applied after a reload problem.
    Stale,
    /// The source is unavailable and no current snapshot can be obtained.
    Unavailable,
}

/// A local service listener managed by the runtime.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RuntimeService {
    /// The protobuf/gRPC client API listener.
    ClientApi,
    /// The raw TACACS+ proxy listener.
    TacacsProxy,
}

/// State of a local service listener.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ListenerState {
    /// The listener is not enabled for this process.
    Disabled,
    /// The listener is enabled but binding has not started.
    Pending,
    /// The listener is creating and configuring its local endpoint.
    Binding,
    /// The endpoint is bound and accepting work.
    Bound,
    /// The listener has stopped accepting work.
    Stopped,
}

/// Aggregate result of observed upstream connection attempts.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UpstreamAvailability {
    /// No conclusive connection attempt has been observed for this server set.
    Unknown,
    /// At least one eligible upstream accepted the latest authoritative attempt.
    Available,
    /// An authoritative attempt exhausted every eligible upstream.
    Unavailable,
}

/// Typed reason why a live process is operating in a degraded state.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum DegradationReason {
    /// The datastore cannot currently be reached.
    DatastoreUnavailable,
    /// The runtime retained an older known-good datastore snapshot.
    DatastoreStale,
    /// Continuous datastore notifications are disconnected.
    ChangeNotificationsUnavailable,
    /// A candidate configuration was rejected while an older snapshot remained active.
    CandidateConfigurationRejected,
    /// Credential resolution failed for a candidate configuration.
    CredentialResolutionFailed,
    /// Validated listener or host-binding settings require process restart.
    RestartRequired,
    /// Every eligible upstream failed an authoritative connection attempt.
    UpstreamsUnavailable,
    /// A runtime invariant or internal component failed.
    InternalFailure,
}

/// Immutable, secret-free view of agent runtime health.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeHealthSnapshot {
    lifecycle: RuntimeLifecycle,
    applied_configuration: bool,
    datastore: DatastoreState,
    continuous_notifications_connected: bool,
    enabled_services: EnabledServices,
    client_api_listener: ListenerState,
    tacacs_proxy_listener: ListenerState,
    eligible_server_count: usize,
    upstream_availability: UpstreamAvailability,
    degradation_reasons: BTreeSet<DegradationReason>,
}

impl RuntimeHealthSnapshot {
    /// Returns the process lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> RuntimeLifecycle {
        self.lifecycle
    }

    /// Returns whether at least one complete validated configuration was applied.
    #[must_use]
    pub const fn has_applied_configuration(&self) -> bool {
        self.applied_configuration
    }

    /// Returns the state of the configured datastore source.
    #[must_use]
    pub const fn datastore(&self) -> DatastoreState {
        self.datastore
    }

    /// Returns whether a continuous change-notification subscription is connected.
    #[must_use]
    pub const fn continuous_notifications_connected(&self) -> bool {
        self.continuous_notifications_connected
    }

    /// Returns the services enabled for this runtime.
    #[must_use]
    pub const fn enabled_services(&self) -> EnabledServices {
        self.enabled_services
    }

    /// Returns the state of a local listener.
    #[must_use]
    pub const fn listener(&self, service: RuntimeService) -> ListenerState {
        match service {
            RuntimeService::ClientApi => self.client_api_listener,
            RuntimeService::TacacsProxy => self.tacacs_proxy_listener,
        }
    }

    /// Returns the number of configured servers eligible for runtime operations.
    #[must_use]
    pub const fn eligible_server_count(&self) -> usize {
        self.eligible_server_count
    }

    /// Returns aggregate observed upstream availability.
    #[must_use]
    pub const fn upstream_availability(&self) -> UpstreamAvailability {
        self.upstream_availability
    }

    /// Returns the typed degradation reasons currently present.
    #[must_use]
    pub const fn degradation_reasons(&self) -> &BTreeSet<DegradationReason> {
        &self.degradation_reasons
    }

    /// Returns whether the initial configuration and listener startup completed.
    ///
    /// Zero eligible servers does not prevent startup from completing. It does
    /// prevent readiness through [`is_readiness_serving`](Self::is_readiness_serving).
    #[must_use]
    pub fn is_startup_serving(&self) -> bool {
        self.accepts_health_requests()
            && self.applied_configuration
            && self.all_enabled_listeners_bound()
    }

    /// Returns whether the process and local health event loop are live.
    ///
    /// Datastore, credential, and upstream outages do not affect liveness.
    #[must_use]
    pub fn is_liveness_serving(&self) -> bool {
        self.accepts_health_requests()
    }

    /// Returns whether business requests may be sent to the agent.
    ///
    /// Readiness requires completed startup and at least one eligible configured
    /// server. Current upstream reachability is deliberately ignored.
    #[must_use]
    pub fn is_readiness_serving(&self) -> bool {
        self.is_startup_serving() && self.eligible_server_count > 0
    }

    fn accepts_health_requests(&self) -> bool {
        matches!(self.lifecycle, RuntimeLifecycle::Starting | RuntimeLifecycle::Serving)
    }

    fn all_enabled_listeners_bound(&self) -> bool {
        (!self.enabled_services.client_api() || self.client_api_listener == ListenerState::Bound)
            && (!self.enabled_services.tacacs_proxy()
                || self.tacacs_proxy_listener == ListenerState::Bound)
    }
}

/// Single writer for runtime health transitions.
///
/// Clones share the same watch channel. Mutation methods publish only when the
/// resulting snapshot differs, which keeps health watches free from duplicate
/// transitions.
#[derive(Debug, Clone)]
pub struct RuntimeHealthPublisher {
    sender: watch::Sender<RuntimeHealthSnapshot>,
}

impl RuntimeHealthPublisher {
    /// Creates health state for the selected local services.
    #[must_use]
    pub fn new(enabled_services: EnabledServices) -> Self {
        let client_api_listener = initial_listener_state(enabled_services.client_api());
        let tacacs_proxy_listener = initial_listener_state(enabled_services.tacacs_proxy());
        let initial = RuntimeHealthSnapshot {
            lifecycle: RuntimeLifecycle::Starting,
            applied_configuration: false,
            datastore: DatastoreState::Loading,
            continuous_notifications_connected: false,
            enabled_services,
            client_api_listener,
            tacacs_proxy_listener,
            eligible_server_count: 0,
            upstream_availability: UpstreamAvailability::Unknown,
            degradation_reasons: BTreeSet::new(),
        };
        let (sender, _) = watch::channel(initial);

        Self { sender }
    }

    /// Subscribes to the current snapshot and subsequent transitions.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<RuntimeHealthSnapshot> {
        self.sender.subscribe()
    }

    /// Returns a clone of the current snapshot without subscribing.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeHealthSnapshot {
        self.sender.borrow().clone()
    }

    /// Publishes a process lifecycle transition.
    pub fn set_lifecycle(&self, lifecycle: RuntimeLifecycle) {
        self.update(|snapshot| snapshot.lifecycle = lifecycle);
    }

    /// Publishes whether a complete validated configuration has been applied.
    pub fn set_applied_configuration(&self, applied: bool) {
        self.update(|snapshot| snapshot.applied_configuration = applied);
    }

    /// Publishes the datastore state.
    pub fn set_datastore(&self, datastore: DatastoreState) {
        self.update(|snapshot| snapshot.datastore = datastore);
    }

    /// Publishes continuous change-notification connectivity.
    pub fn set_continuous_notifications_connected(&self, connected: bool) {
        self.update(|snapshot| snapshot.continuous_notifications_connected = connected);
    }

    /// Publishes a local listener transition.
    ///
    /// Returns `false` without changing the snapshot when the selected listener
    /// is disabled. This allows shared lifecycle code to remain race-safe while
    /// still surfacing an invalid ownership assumption to its caller.
    #[must_use]
    pub fn set_listener(&self, service: RuntimeService, state: ListenerState) -> bool {
        if !self.service_enabled(service) {
            return false;
        }

        self.update(|snapshot| match service {
            RuntimeService::ClientApi => snapshot.client_api_listener = state,
            RuntimeService::TacacsProxy => snapshot.tacacs_proxy_listener = state,
        });
        true
    }

    /// Publishes the count of configured servers eligible for runtime operations.
    pub fn set_eligible_server_count(&self, count: usize) {
        self.update(|snapshot| snapshot.eligible_server_count = count);
    }

    /// Publishes aggregate observed upstream availability.
    pub fn set_upstream_availability(&self, availability: UpstreamAvailability) {
        self.update(|snapshot| snapshot.upstream_availability = availability);
    }

    /// Adds or removes a typed degradation reason.
    pub fn set_degraded(&self, reason: DegradationReason, degraded: bool) {
        self.update(|snapshot| {
            if degraded {
                snapshot.degradation_reasons.insert(reason);
            } else {
                snapshot.degradation_reasons.remove(&reason);
            }
        });
    }

    fn service_enabled(&self, service: RuntimeService) -> bool {
        let enabled_services = self.sender.borrow().enabled_services;
        match service {
            RuntimeService::ClientApi => enabled_services.client_api(),
            RuntimeService::TacacsProxy => enabled_services.tacacs_proxy(),
        }
    }

    fn update(&self, mutation: impl FnOnce(&mut RuntimeHealthSnapshot)) {
        let mut next = self.snapshot();
        mutation(&mut next);
        if next.lifecycle == RuntimeLifecycle::Starting
            && next.applied_configuration
            && next.all_enabled_listeners_bound()
        {
            next.lifecycle = RuntimeLifecycle::Serving;
        }
        if next != *self.sender.borrow() {
            self.sender.send_replace(next);
        }
    }
}

fn initial_listener_state(enabled: bool) -> ListenerState {
    if enabled {
        ListenerState::Pending
    } else {
        ListenerState::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_publishes_starting_state_for_enabled_services() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::BOTH);
        let snapshot = publisher.snapshot();

        assert_eq!(snapshot.lifecycle(), RuntimeLifecycle::Starting);
        assert_eq!(snapshot.datastore(), DatastoreState::Loading);
        assert_eq!(snapshot.listener(RuntimeService::ClientApi), ListenerState::Pending);
        assert_eq!(snapshot.listener(RuntimeService::TacacsProxy), ListenerState::Pending);
        assert_eq!(snapshot.upstream_availability(), UpstreamAvailability::Unknown);
        assert!(snapshot.is_liveness_serving());
        assert!(!snapshot.is_startup_serving());
        assert!(!snapshot.is_readiness_serving());
    }

    #[test]
    fn startup_waits_for_configuration_and_every_enabled_listener() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::BOTH);
        publisher.set_applied_configuration(true);
        publisher.set_eligible_server_count(1);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));

        assert!(!publisher.snapshot().is_startup_serving());

        assert!(publisher.set_listener(RuntimeService::TacacsProxy, ListenerState::Bound));
        let snapshot = publisher.snapshot();
        assert_eq!(snapshot.lifecycle(), RuntimeLifecycle::Serving);
        assert!(snapshot.is_startup_serving());
        assert!(snapshot.is_readiness_serving());
    }

    #[test]
    fn startup_allows_zero_eligible_servers_but_readiness_does_not() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        publisher.set_applied_configuration(true);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));

        let snapshot = publisher.snapshot();
        assert!(snapshot.is_startup_serving());
        assert!(snapshot.is_liveness_serving());
        assert!(!snapshot.is_readiness_serving());
        assert_eq!(snapshot.listener(RuntimeService::TacacsProxy), ListenerState::Disabled);
    }

    #[test]
    fn upstream_unavailability_does_not_withdraw_readiness_or_liveness() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        publisher.set_applied_configuration(true);
        publisher.set_eligible_server_count(2);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));
        publisher.set_upstream_availability(UpstreamAvailability::Unavailable);
        publisher.set_degraded(DegradationReason::UpstreamsUnavailable, true);

        let snapshot = publisher.snapshot();
        assert!(snapshot.is_liveness_serving());
        assert!(snapshot.is_readiness_serving());
        assert!(snapshot
            .degradation_reasons()
            .contains(&DegradationReason::UpstreamsUnavailable));
    }

    #[test]
    fn stale_datastore_retains_readiness_from_known_good_configuration() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        publisher.set_applied_configuration(true);
        publisher.set_eligible_server_count(1);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));
        publisher.set_datastore(DatastoreState::Stale);
        publisher.set_degraded(DegradationReason::DatastoreStale, true);

        let snapshot = publisher.snapshot();
        assert!(snapshot.is_readiness_serving());
        assert_eq!(snapshot.datastore(), DatastoreState::Stale);
    }

    #[test]
    fn restart_required_is_degraded_without_withdrawing_readiness() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        publisher.set_applied_configuration(true);
        publisher.set_eligible_server_count(1);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));

        publisher.set_degraded(DegradationReason::RestartRequired, true);
        assert!(publisher.snapshot().is_readiness_serving());
        assert!(publisher
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::RestartRequired));

        publisher.set_degraded(DegradationReason::RestartRequired, false);
        assert!(!publisher
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::RestartRequired));
    }

    #[test]
    fn draining_withdraws_every_health_view() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        publisher.set_applied_configuration(true);
        publisher.set_eligible_server_count(1);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));
        publisher.set_lifecycle(RuntimeLifecycle::Serving);
        publisher.set_lifecycle(RuntimeLifecycle::Draining);

        let snapshot = publisher.snapshot();
        assert!(!snapshot.is_startup_serving());
        assert!(!snapshot.is_liveness_serving());
        assert!(!snapshot.is_readiness_serving());
    }

    #[tokio::test]
    async fn publisher_sends_changed_snapshots_only() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let mut receiver = publisher.subscribe();

        publisher.set_datastore(DatastoreState::Loading);
        assert!(receiver.has_changed().is_ok_and(|changed| !changed));

        publisher.set_datastore(DatastoreState::Current);
        receiver
            .changed()
            .await
            .expect("publisher should remain alive");
        assert_eq!(receiver.borrow().datastore(), DatastoreState::Current);
    }

    #[test]
    fn disabled_listener_rejects_transitions() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);

        assert!(!publisher.set_listener(RuntimeService::TacacsProxy, ListenerState::Bound));
        assert_eq!(
            publisher.snapshot().listener(RuntimeService::TacacsProxy),
            ListenerState::Disabled
        );
    }

    #[test]
    fn snapshot_debug_output_contains_no_configuration_or_secret_values() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::BOTH);
        publisher.set_degraded(DegradationReason::CredentialResolutionFailed, true);
        let output = format!("{:?}", publisher.snapshot());

        for forbidden in [
            "redis://",
            "unix://",
            "192.0.2.10",
            "credential-reference",
            "test-secret",
        ] {
            assert!(!output.contains(forbidden), "snapshot exposed {forbidden}");
        }
    }
}
