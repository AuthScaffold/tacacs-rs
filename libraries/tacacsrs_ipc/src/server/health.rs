//! Standard `grpc.health.v1.Health` mapping for the IPC listener.

use tokio::sync::watch;
use tonic_health::ServingStatus;
use tonic_health::pb::health_server::HealthServer;
use tonic_health::server::{HealthReporter, HealthService};

use crate::health::{
    LIVENESS_HEALTH_SERVICE, OVERALL_HEALTH_SERVICE, READINESS_HEALTH_SERVICE,
    STARTUP_HEALTH_SERVICE, TACACS_AGENT_HEALTH_SERVICE,
};

/// Neutral startup, liveness, and readiness state for the IPC listener.
///
/// The host projects its own runtime health into this transport-neutral form.
/// The IPC listener maps each field to the standard gRPC health service names.
/// This type contains no secret values and no host-specific reasons.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct HealthStatus {
    /// Whether startup probes report serving.
    pub startup_serving: bool,
    /// Whether liveness probes report serving.
    pub liveness_serving: bool,
    /// Whether readiness, overall, and business probes report serving.
    pub readiness_serving: bool,
}

/// Standard health service and its neutral status reporter.
pub(super) struct StandardHealth {
    reporter: HealthReporter,
    receiver: watch::Receiver<HealthStatus>,
}

impl StandardHealth {
    /// Creates and initializes each supported health service name.
    pub(super) async fn new(
        receiver: watch::Receiver<HealthStatus>,
    ) -> (Self, HealthServer<HealthService>) {
        let reporter = HealthReporter::new();
        let service = HealthService::from_health_reporter(reporter.clone());
        let health = Self { reporter, receiver };
        health.publish_current().await;
        (health, HealthServer::new(service))
    }

    /// Publishes changes until the listener stops.
    ///
    /// On shutdown the listener withdraws every health service before it clears
    /// the service names. Withdrawal does not depend on the host's last readiness
    /// value, so a draining listener never reports serving.
    pub(super) async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        if *shutdown.borrow() {
            self.withdraw().await;
            self.close_watches().await;
            return;
        }
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        self.withdraw().await;
                        self.close_watches().await;
                        return;
                    }
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
        let status = *self.receiver.borrow();
        self.set_status(STARTUP_HEALTH_SERVICE, status.startup_serving)
            .await;
        self.set_status(LIVENESS_HEALTH_SERVICE, status.liveness_serving)
            .await;
        self.set_status(READINESS_HEALTH_SERVICE, status.readiness_serving)
            .await;
        self.set_status(OVERALL_HEALTH_SERVICE, status.readiness_serving)
            .await;
        self.set_status(TACACS_AGENT_HEALTH_SERVICE, status.readiness_serving)
            .await;
    }

    /// Reports every supported health service as not serving.
    async fn withdraw(&self) {
        for service_name in [
            STARTUP_HEALTH_SERVICE,
            LIVENESS_HEALTH_SERVICE,
            READINESS_HEALTH_SERVICE,
            OVERALL_HEALTH_SERVICE,
            TACACS_AGENT_HEALTH_SERVICE,
        ] {
            self.set_status(service_name, false).await;
        }
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
    use tonic::Request;
    use tonic_health::pb::HealthCheckRequest;
    use tonic_health::pb::health_check_response::ServingStatus as WireServingStatus;
    use tonic_health::pb::health_server::Health;

    use super::*;

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
        let (sender, receiver) = watch::channel(HealthStatus {
            startup_serving: false,
            liveness_serving: true,
            readiness_serving: false,
        });
        let (health, _) = StandardHealth::new(receiver).await;
        let service = HealthService::from_health_reporter(health.reporter.clone());

        assert_eq!(check(&service, STARTUP_HEALTH_SERVICE).await, WireServingStatus::NotServing,);
        assert_eq!(check(&service, LIVENESS_HEALTH_SERVICE).await, WireServingStatus::Serving,);
        assert_eq!(check(&service, READINESS_HEALTH_SERVICE).await, WireServingStatus::NotServing,);

        sender
            .send(HealthStatus {
                startup_serving: true,
                liveness_serving: true,
                readiness_serving: true,
            })
            .expect("the receiver must stay open");
        health.publish_current().await;

        assert_eq!(check(&service, STARTUP_HEALTH_SERVICE).await, WireServingStatus::Serving,);
        assert_eq!(check(&service, READINESS_HEALTH_SERVICE).await, WireServingStatus::Serving,);
    }

    #[tokio::test]
    async fn watch_receives_readiness_transition_and_shutdown_withdrawal() {
        let (status_sender, status_receiver) = watch::channel(HealthStatus::default());
        let (health, _) = StandardHealth::new(status_receiver).await;
        let service = HealthService::from_health_reporter(health.reporter.clone());
        let mut stream = service
            .watch(Request::new(HealthCheckRequest {
                service: READINESS_HEALTH_SERVICE.to_owned(),
            }))
            .await
            .expect("the health watch must open")
            .into_inner();
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let bridge = tokio::spawn(health.run(shutdown_receiver));

        let initial = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("the stream must contain an initial status")
            .expect("the initial status must be valid");
        assert_eq!(
            WireServingStatus::try_from(initial.status).expect("the status must be known"),
            WireServingStatus::NotServing,
        );

        status_sender
            .send(HealthStatus {
                startup_serving: true,
                liveness_serving: true,
                readiness_serving: true,
            })
            .expect("the receiver must stay open");
        let serving = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("the stream must contain a serving status")
            .expect("the serving status must be valid");
        assert_eq!(
            WireServingStatus::try_from(serving.status).expect("the status must be known"),
            WireServingStatus::Serving,
        );

        shutdown_sender
            .send(true)
            .expect("the receiver must stay open");
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
