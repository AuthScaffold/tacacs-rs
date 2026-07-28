//! Standard `grpc.health.v1.Health` mapping for the Client API listener.

use tacacsrs_agent_client::health::{
    LIVENESS_HEALTH_SERVICE, OVERALL_HEALTH_SERVICE, READINESS_HEALTH_SERVICE,
    STARTUP_HEALTH_SERVICE, TACACS_AGENT_HEALTH_SERVICE,
};
use tokio::sync::watch;
use tonic_health::ServingStatus;
use tonic_health::pb::health_server::HealthServer;
use tonic_health::server::{HealthReporter, HealthService};

use crate::runtime::{RuntimeHealthSnapshot, ShutdownReceiver};

/// Standard health service plus its runtime snapshot reporter.
pub(super) struct StandardHealth {
    reporter: HealthReporter,
    receiver: watch::Receiver<RuntimeHealthSnapshot>,
}

impl StandardHealth {
    /// Creates and initializes all supported standard health service names.
    pub(super) async fn new(
        receiver: watch::Receiver<RuntimeHealthSnapshot>,
    ) -> (Self, HealthServer<HealthService>) {
        let reporter = HealthReporter::new();
        let service = HealthService::from_health_reporter(reporter.clone());
        let health = Self { reporter, receiver };
        health.publish_current().await;
        (health, HealthServer::new(service))
    }

    /// Publishes transitions until listener shutdown.
    pub(super) async fn run(mut self, shutdown: ShutdownReceiver) {
        loop {
            tokio::select! {
                () = shutdown.clone().wait() => {
                    self.publish_current().await;
                    return;
                }
                result = self.receiver.changed() => {
                    if result.is_err() {
                        return;
                    }
                    self.publish_current().await;
                }
            }
        }
    }

    async fn publish_current(&self) {
        let snapshot = self.receiver.borrow().clone();
        self.set_status(STARTUP_HEALTH_SERVICE, snapshot.is_startup_serving())
            .await;
        self.set_status(LIVENESS_HEALTH_SERVICE, snapshot.is_liveness_serving())
            .await;
        self.set_status(READINESS_HEALTH_SERVICE, snapshot.is_readiness_serving())
            .await;
        self.set_status(OVERALL_HEALTH_SERVICE, snapshot.is_readiness_serving())
            .await;
        self.set_status(TACACS_AGENT_HEALTH_SERVICE, snapshot.is_readiness_serving())
            .await;
    }

    async fn set_status(&self, service_name: &str, serving: bool) {
        let status = if serving {
            ServingStatus::Serving
        } else {
            ServingStatus::NotServing
        };
        self.reporter.set_service_status(service_name, status).await;
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_agent_client::health::{
        LIVENESS_HEALTH_SERVICE, READINESS_HEALTH_SERVICE, STARTUP_HEALTH_SERVICE,
    };
    use tonic::Request;
    use tonic_health::pb::HealthCheckRequest;
    use tonic_health::pb::health_check_response::ServingStatus as WireServingStatus;
    use tonic_health::pb::health_server::Health;

    use super::*;
    use crate::runtime::{ListenerState, RuntimeHealthPublisher, RuntimeService, ShutdownCoordinator};
    use crate::EnabledServices;

    async fn check(service: &HealthService, service_name: &str) -> WireServingStatus {
        let response = service
            .check(Request::new(HealthCheckRequest {
                service: service_name.to_owned(),
            }))
            .await
            .expect("health check should succeed")
            .into_inner();
        WireServingStatus::try_from(response.status).expect("known serving status")
    }

    #[tokio::test]
    async fn check_maps_startup_liveness_and_readiness_independently() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let (health, _) = StandardHealth::new(publisher.subscribe()).await;
        let service = HealthService::from_health_reporter(health.reporter.clone());

        assert_eq!(check(&service, STARTUP_HEALTH_SERVICE).await, WireServingStatus::NotServing,);
        assert_eq!(check(&service, LIVENESS_HEALTH_SERVICE).await, WireServingStatus::Serving,);
        assert_eq!(check(&service, READINESS_HEALTH_SERVICE).await, WireServingStatus::NotServing,);

        publisher.set_applied_configuration(true);
        publisher.set_eligible_server_count(1);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));
        health.publish_current().await;

        assert_eq!(check(&service, STARTUP_HEALTH_SERVICE).await, WireServingStatus::Serving,);
        assert_eq!(check(&service, READINESS_HEALTH_SERVICE).await, WireServingStatus::Serving,);
    }

    #[tokio::test]
    async fn watch_receives_readiness_transition_and_shutdown_withdrawal() {
        let publisher = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let (health, _) = StandardHealth::new(publisher.subscribe()).await;
        let service = HealthService::from_health_reporter(health.reporter.clone());
        let mut stream = service
            .watch(Request::new(HealthCheckRequest {
                service: READINESS_HEALTH_SERVICE.to_owned(),
            }))
            .await
            .expect("health watch should open")
            .into_inner();
        let shutdown = ShutdownCoordinator::new(publisher.clone());
        let bridge = tokio::spawn(health.run(shutdown.subscribe()));

        let initial = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("initial status")
            .expect("valid initial status");
        assert_eq!(
            WireServingStatus::try_from(initial.status).expect("known status"),
            WireServingStatus::NotServing,
        );

        publisher.set_applied_configuration(true);
        publisher.set_eligible_server_count(1);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));
        let serving = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("serving status")
            .expect("valid serving status");
        assert_eq!(
            WireServingStatus::try_from(serving.status).expect("known status"),
            WireServingStatus::Serving,
        );

        shutdown.initiate_shutdown();
        let withdrawn = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("withdrawn status")
            .expect("valid withdrawn status");
        assert_eq!(
            WireServingStatus::try_from(withdrawn.status).expect("known status"),
            WireServingStatus::NotServing,
        );
        bridge.await.expect("bridge should stop");
    }
}
