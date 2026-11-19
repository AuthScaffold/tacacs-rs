//! Projects the runtime health snapshot and the health registry into the IPC
//! health details reply.
//!
//! The reply has one component entry for each check in the [`HealthRegistry`].
//! The mapping has no list of components. Each match is exhaustive. A new runtime state does not compile until it has
//! a value in `proto/tacacsrs_agent_health.proto`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::{
    DatastoreState, DegradationReason, ListenerState, RuntimeHealthPublisher,
    RuntimeHealthSnapshot, RuntimeLifecycle, RuntimeService, UpstreamAvailability,
};
use tacacsrs_ipc::proto;
use tacacsrs_lifecycle::{HealthEntry, HealthRegistry, HealthStatus};

/// Serves the runtime health snapshot and the registered checks as health
/// details.
pub(super) struct AgentHealthDetails {
    pub(super) health: RuntimeHealthPublisher,
    pub(super) registry: Arc<HealthRegistry>,
}

#[async_trait]
impl tacacsrs_ipc::HealthDetailsProvider for AgentHealthDetails {
    async fn health_details(&self) -> proto::HealthDetailsReply {
        let mut reply = reply(&self.health.snapshot());
        reply.components = self
            .registry
            .check_all()
            .await
            .iter()
            .map(component)
            .collect();
        reply
    }
}

fn component(entry: &HealthEntry) -> proto::ComponentHealth {
    proto::ComponentHealth {
        group: entry.group.to_owned(),
        name: entry.name.to_owned(),
        status: component_status(entry.status) as i32,
        description: entry.description.clone(),
        duration_micros: u64::try_from(entry.duration.as_micros()).unwrap_or(u64::MAX),
    }
}

const fn component_status(value: HealthStatus) -> proto::ComponentHealthStatus {
    match value {
        HealthStatus::Healthy => proto::ComponentHealthStatus::Healthy,
        HealthStatus::Degraded => proto::ComponentHealthStatus::Degraded,
        HealthStatus::Unhealthy => proto::ComponentHealthStatus::Unhealthy,
    }
}

fn reply(snapshot: &RuntimeHealthSnapshot) -> proto::HealthDetailsReply {
    let services = snapshot.enabled_services();
    let listeners = [
        (RuntimeService::ClientApi, services.client_api()),
        (RuntimeService::TacacsProxy, services.tacacs_proxy()),
    ]
    .into_iter()
    .map(|(service, enabled)| proto::ListenerHealth {
        service: runtime_service(service) as i32,
        enabled,
        state: listener_state(snapshot.listener(service)) as i32,
    })
    .collect();
    let materialization = snapshot.materialization_revision();
    proto::HealthDetailsReply {
        lifecycle: lifecycle(snapshot.lifecycle()) as i32,
        startup: snapshot.is_startup_serving(),
        liveness: snapshot.is_liveness_serving(),
        readiness: snapshot.is_readiness_serving(),
        listening: snapshot.is_listening(),
        applied_configuration: snapshot.has_applied_configuration(),
        datastore: datastore(snapshot.datastore()) as i32,
        notifications_connected: snapshot.continuous_notifications_connected(),
        listeners,
        eligible_server_count: u64::try_from(snapshot.eligible_server_count()).unwrap_or(u64::MAX),
        upstream_availability: upstream(snapshot.upstream_availability()) as i32,
        watchdog: Some(proto::WatchdogHealth {
            armed: snapshot.is_upstream_watchdog_armed(),
            server_set_epoch: snapshot.upstream_watchdog_epoch(),
        }),
        degradation_reasons: snapshot
            .degradation_reasons()
            .iter()
            .map(|reason| degradation(*reason) as i32)
            .collect(),
        revisions: Some(proto::HealthRevisions {
            runtime_generation: snapshot.runtime_generation().map(|value| value.value()),
            applied_policy: snapshot
                .applied_policy_revision()
                .map(|value| value.value()),
            materialized_source: materialization.map(|value| value.source().value()),
            materialized_credentials: materialization.map(|value| value.credentials().value()),
            source_recovery: snapshot
                .source_recovery_revision()
                .map(|value| value.value()),
        }),
        credential_validity: snapshot.credential_validity().map(|validity| {
            proto::CredentialValidityWindow {
                valid_from_unix_seconds: validity.valid_from().map(unix_seconds),
                valid_until_unix_seconds: validity.valid_until().map(unix_seconds),
            }
        }),
        components: Vec::new(),
    }
}

/// Converts a time to signed seconds since the Unix epoch. Values saturate.
fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_secs()).map_or(i64::MIN, |value| -value),
    }
}

const fn lifecycle(value: RuntimeLifecycle) -> proto::RuntimeLifecycle {
    match value {
        RuntimeLifecycle::Starting => proto::RuntimeLifecycle::Starting,
        RuntimeLifecycle::Serving => proto::RuntimeLifecycle::Serving,
        RuntimeLifecycle::Draining => proto::RuntimeLifecycle::Draining,
        RuntimeLifecycle::Stopped => proto::RuntimeLifecycle::Stopped,
        RuntimeLifecycle::Failed => proto::RuntimeLifecycle::Failed,
    }
}

const fn datastore(value: DatastoreState) -> proto::DatastoreState {
    match value {
        DatastoreState::Loading => proto::DatastoreState::Loading,
        DatastoreState::Current => proto::DatastoreState::Current,
        DatastoreState::Stale => proto::DatastoreState::Stale,
        DatastoreState::Unavailable => proto::DatastoreState::Unavailable,
    }
}

const fn runtime_service(value: RuntimeService) -> proto::RuntimeService {
    match value {
        RuntimeService::ClientApi => proto::RuntimeService::ClientApi,
        RuntimeService::TacacsProxy => proto::RuntimeService::TacacsProxy,
    }
}

const fn listener_state(value: ListenerState) -> proto::ListenerState {
    match value {
        ListenerState::Disabled => proto::ListenerState::Disabled,
        ListenerState::Pending => proto::ListenerState::Pending,
        ListenerState::Binding => proto::ListenerState::Binding,
        ListenerState::Bound => proto::ListenerState::Bound,
        ListenerState::Stopped => proto::ListenerState::Stopped,
    }
}

const fn upstream(value: UpstreamAvailability) -> proto::UpstreamAvailability {
    match value {
        UpstreamAvailability::Unknown => proto::UpstreamAvailability::Unknown,
        UpstreamAvailability::Available => proto::UpstreamAvailability::Available,
        UpstreamAvailability::Unavailable => proto::UpstreamAvailability::Unavailable,
    }
}

const fn degradation(value: DegradationReason) -> proto::DegradationReason {
    use proto::DegradationReason as Wire;
    match value {
        DegradationReason::RetainedAfterClear => Wire::RetainedAfterClear,
        DegradationReason::DatastoreUnavailable => Wire::DatastoreUnavailable,
        DegradationReason::DatastoreStale => Wire::DatastoreStale,
        DegradationReason::SourceExpired => Wire::SourceExpired,
        DegradationReason::CredentialsStale => Wire::CredentialsStale,
        DegradationReason::CredentialsExpired => Wire::CredentialsExpired,
        DegradationReason::ChangeNotificationsUnavailable => Wire::ChangeNotificationsUnavailable,
        DegradationReason::CredentialNotificationsUnavailable => {
            Wire::CredentialNotificationsUnavailable
        }
        DegradationReason::CandidateConfigurationRejected => Wire::CandidateConfigurationRejected,
        DegradationReason::CandidatePolicyRejected => Wire::CandidatePolicyRejected,
        DegradationReason::SourceConfigurationInvalid => Wire::SourceConfigurationInvalid,
        DegradationReason::CredentialResolutionFailed => Wire::CredentialResolutionFailed,
        DegradationReason::UpstreamsUnavailable => Wire::UpstreamsUnavailable,
        DegradationReason::UpstreamWatchdogFailed => Wire::UpstreamWatchdogFailed,
        DegradationReason::UpstreamWatchdogPending => Wire::UpstreamWatchdogPending,
        DegradationReason::InternalFailure => Wire::InternalFailure,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::EnabledServices;

    struct Waiting;

    #[async_trait]
    impl tacacsrs_lifecycle::HealthCheck for Waiting {
        async fn check(
            &self,
            _: &tacacsrs_lifecycle::HealthCheckContext,
        ) -> Result<tacacsrs_lifecycle::HealthCheckResult, tacacsrs_lifecycle::BoxError> {
            Ok(tacacsrs_lifecycle::HealthCheckResult::degraded().with_description("waits"))
        }
    }

    impl tacacsrs_lifecycle::HealthMember<tacacsrs_lifecycle::ComponentHealth> for Waiting {
        fn name(&self) -> &'static str {
            "waiting"
        }
    }

    #[tokio::test]
    async fn reply_reports_the_current_snapshot_and_its_probe_results() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        health.set_lifecycle(RuntimeLifecycle::Serving);
        health.set_datastore(DatastoreState::Stale);
        health.set_upstream_availability(UpstreamAvailability::Available);
        health.set_eligible_server_count(2);
        health.set_degraded(DegradationReason::DatastoreStale, true);
        health.set_degraded(DegradationReason::RetainedAfterClear, true);
        health.set_listener(RuntimeService::ClientApi, ListenerState::Bound);
        let member: Arc<dyn tacacsrs_lifecycle::HealthMember<tacacsrs_lifecycle::ComponentHealth>> =
            Arc::new(Waiting);
        let registry =
            HealthRegistry::new(vec![tacacsrs_lifecycle::HealthRegistration::new(member)]).unwrap();
        let details = AgentHealthDetails {
            health: health.clone(),
            registry: Arc::new(registry),
        };
        let reply = tacacsrs_ipc::HealthDetailsProvider::health_details(&details).await;
        let snapshot = health.snapshot();

        assert_eq!(reply.lifecycle(), proto::RuntimeLifecycle::Serving);
        assert_eq!(reply.datastore(), proto::DatastoreState::Stale);
        assert_eq!(reply.upstream_availability(), proto::UpstreamAvailability::Available);
        assert_eq!(reply.eligible_server_count, 2);
        assert_eq!(
            (reply.startup, reply.liveness, reply.readiness, reply.listening),
            (
                snapshot.is_startup_serving(),
                snapshot.is_liveness_serving(),
                snapshot.is_readiness_serving(),
                snapshot.is_listening()
            )
        );
        assert_eq!(
            reply.degradation_reasons().collect::<Vec<_>>(),
            [
                proto::DegradationReason::RetainedAfterClear,
                proto::DegradationReason::DatastoreStale
            ]
        );
        let listeners: Vec<_> = reply
            .listeners
            .iter()
            .map(|listener| (listener.service(), listener.enabled, listener.state()))
            .collect();
        assert_eq!(
            listeners,
            [
                (proto::RuntimeService::ClientApi, true, proto::ListenerState::Bound),
                (proto::RuntimeService::TacacsProxy, false, proto::ListenerState::Disabled),
            ]
        );
        assert!(reply.credential_validity.is_none());
        let components: Vec<_> = reply
            .components
            .iter()
            .map(|entry| {
                (entry.group.as_str(), entry.name.as_str(), entry.status(), entry.description())
            })
            .collect();
        assert_eq!(
            components,
            [("component", "waiting", proto::ComponentHealthStatus::Degraded, "waits")]
        );
    }

    #[test]
    fn times_before_the_epoch_are_negative() {
        assert_eq!(unix_seconds(UNIX_EPOCH + Duration::from_secs(5)), 5);
        assert_eq!(unix_seconds(UNIX_EPOCH - Duration::from_secs(5)), -5);
    }
}
