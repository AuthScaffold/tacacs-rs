//! Stable service names used with the standard gRPC health protocol.

use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient as GrpcHealthClient;

use crate::endpoint::connect_channel;
use crate::IpcEndpoint;

/// Overall health service name.
///
/// The empty name follows the gRPC health protocol and maps to agent readiness.
pub const OVERALL_HEALTH_SERVICE: &str = "";

/// Business RPC service represented by agent readiness.
pub const TACACS_AGENT_HEALTH_SERVICE: &str = "tacacsrs.agent.v1.TacacsAgent";

/// Startup probe service name.
pub const STARTUP_HEALTH_SERVICE: &str = "tacacsrs.agent.health.v1.Startup";

/// Liveness probe service name.
pub const LIVENESS_HEALTH_SERVICE: &str = "tacacsrs.agent.health.v1.Liveness";

/// Readiness probe service name.
pub const READINESS_HEALTH_SERVICE: &str = "tacacsrs.agent.health.v1.Readiness";

/// Standard gRPC health client over the same local transport as [`crate::ServiceClient`].
#[derive(Debug, Clone)]
pub struct HealthClient {
    client: GrpcHealthClient<tonic::transport::Channel>,
}

impl HealthClient {
    /// Connects to the standard health service on a local IPC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the local endpoint cannot be reached.
    pub async fn connect(endpoint: &IpcEndpoint) -> anyhow::Result<Self> {
        let channel = connect_channel(endpoint).await?;
        Ok(Self {
            client: GrpcHealthClient::new(channel),
        })
    }

    /// Gets the status of one standard gRPC health service name.
    ///
    /// # Errors
    ///
    /// Returns the standard gRPC status if the name is unknown. It also returns
    /// this status for protocol or transport errors.
    pub async fn check(&mut self, service_name: &str) -> Result<ServingStatus, tonic::Status> {
        let response = self
            .client
            .check(HealthCheckRequest {
                service: service_name.to_owned(),
            })
            .await?
            .into_inner();
        Ok(ServingStatus::try_from(response.status).unwrap_or(ServingStatus::Unknown))
    }
}
