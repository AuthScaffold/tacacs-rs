//! Detailed runtime health over the existing local IPC channel.
//!
//! The standard gRPC health service gives one status for each probe name. The
//! `AgentHealth` service in `proto/tacacsrs_agent_health.proto` gives the facts
//! behind those statuses: the lifecycle, the datastore and listener states, the
//! upstream availability, the watchdog state, and the degradation reasons.
//! The reply also contains the result of each health check that a component
//! registered.
//!
//! A host supplies a [`HealthDetailsProvider`]. The listener serves the
//! provider on the same socket as the other IPC services. Use
//! [`HealthClient::details`](crate::HealthClient::details) to read the reply.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::proto;

/// The largest request that the `AgentHealth` service decodes.
///
/// The request has no fields. The limit rejects other payloads early.
pub(crate) const MAX_REQUEST_BYTES: usize = 64;

/// Supplies one consistent, secret-free report of the runtime health.
///
/// The implementation must not do upstream TACACS+ I/O, and it must limit the
/// time of each check that it runs. The reply must not contain credentials,
/// server addresses, or request payloads.
#[tonic::async_trait]
pub trait HealthDetailsProvider: Send + Sync + 'static {
    /// Returns the current runtime health.
    async fn health_details(&self) -> proto::HealthDetailsReply;
}

pub(crate) struct AgentHealthService(pub(crate) Arc<dyn HealthDetailsProvider>);

#[tonic::async_trait]
impl proto::agent_health_server::AgentHealth for AgentHealthService {
    async fn details(
        &self,
        _request: Request<proto::HealthDetailsRequest>,
    ) -> Result<Response<proto::HealthDetailsReply>, Status> {
        Ok(Response::new(self.0.health_details().await))
    }
}
