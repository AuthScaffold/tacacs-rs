//! Standard `grpc.health.v1.Health` mapping for the client API listener.

use tacacsrs_agent_client::health::{
    LIVENESS_HEALTH_SERVICE, OVERALL_HEALTH_SERVICE, READINESS_HEALTH_SERVICE,
    STARTUP_HEALTH_SERVICE, TACACS_AGENT_HEALTH_SERVICE,
};
use tokio::sync::watch;
use tonic_health::ServingStatus;
use tonic_health::pb::health_server::HealthServer;
use tonic_health::server::{HealthReporter, HealthService};

use crate::runtime::{RuntimeHealthSnapshot, ShutdownReceiver};

/// Standard health service and its runtime snapshot reporter.
pub(super) struct StandardHealth {
    reporter: HealthReporter,
    receiver: watch::Receiver<RuntimeHealthSnapshot>,
}

impl StandardHealth {
    /// Creates and initializes each supported health service name.
    pub(super) async fn new(
        receiver: watch::Receiver<RuntimeHealthSnapshot>,
    ) -> (Self, HealthServer<HealthService>) {
        let reporter = HealthReporter::new();
        let service = HealthService::from_health_reporter(reporter.clone());
        let health = Self { reporter, receiver };
        health.publish_current().await;
        (health, HealthServer::new(service))
    }

    /// Publishes changes until the listener stops.
    pub(super) async fn run(mut self, shutdown: ShutdownReceiver) {
        loop {
            tokio::select! {
                () = shutdown.clone().wait() => {
                    self.publish_current().await;
                    self.close_watches().await;
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

    async fn close_watches(&mut self) {
        for service_name in [
            STARTUP_HEALTH_SERVICE,
            LIVENESS_HEALTH_SERVICE,
            READINESS_HEALTH_SERVICE,
            OVERALL_HEALTH_SERVICE,
            TACACS_AGENT_HEALTH_SERVICE,
        ] {
            self.reporter.clear_service_status(service_name).await;
        }
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
            .expect("the health check must succeed")
            .into_inner();
        WireServingStatus::try_from(response.status).expect("the serving status must be known")
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
            .expect("the health watch must open")
            .into_inner();
        let shutdown = ShutdownCoordinator::new(publisher.clone());
        let bridge = tokio::spawn(health.run(shutdown.subscribe()));

        let initial = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("the stream must contain an initial status")
            .expect("the initial status must be valid");
        assert_eq!(
            WireServingStatus::try_from(initial.status).expect("the status must be known"),
            WireServingStatus::NotServing,
        );

        publisher.set_applied_configuration(true);
        publisher.set_eligible_server_count(1);
        assert!(publisher.set_listener(RuntimeService::ClientApi, ListenerState::Bound));
        let serving = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("the stream must contain a serving status")
            .expect("the serving status must be valid");
        assert_eq!(
            WireServingStatus::try_from(serving.status).expect("the status must be known"),
            WireServingStatus::Serving,
        );

        shutdown.initiate_shutdown();
        let withdrawn = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("the stream must contain a withdrawn status")
            .expect("the withdrawn status must be valid");
        assert_eq!(
            WireServingStatus::try_from(withdrawn.status).expect("the status must be known"),
            WireServingStatus::NotServing,
        );
        bridge.await.expect("the bridge must stop");
        assert!(tokio_stream::StreamExt::next(&mut stream).await.is_none());
    }
}
