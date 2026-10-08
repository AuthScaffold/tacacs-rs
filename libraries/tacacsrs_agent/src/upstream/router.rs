//! Per-service view over the shared upstream manager.
//!
//! [`UpstreamManager`] holds state for every local service. A service must not
//! see all of it. [`OperationRouter`] binds one [`PolicyService`] identity at
//! construction and exposes only the operations that a request path needs:
//! admission, plan construction, server binding, and outcome recording.
//!
//! This keeps `PolicyService` out of every call site and stops a service from
//! reading state that belongs to another service.

use std::sync::Arc;

use crate::config::PolicyService;

use super::admission::{AdmissionError, AdmissionPermit};
use tacacsrs_networking::retry::FailoverPlan;
use super::manager::{BoundServer, RoutingLease, UpstreamManager};
use super::operation::OperationKind;

/// Routing and admission entry point for one local service.
#[derive(Clone)]
pub(crate) struct OperationRouter {
    manager: Arc<UpstreamManager>,
    service: PolicyService,
}

/// Captures one request's routing inputs across all of its attempts.
pub(crate) struct RequestRouting {
    manager: Arc<UpstreamManager>,
    lease: RoutingLease,
}

impl RequestRouting {
    pub(crate) fn failover_plan(&self) -> FailoverPlan {
        self.lease.failover_plan()
    }

    pub(crate) async fn bind(&self) -> anyhow::Result<BoundServer> {
        self.manager.bind_request(&self.lease).await
    }

    pub(crate) async fn admit(
        &self,
        body_length: usize,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.manager.admit_request(&self.lease, body_length).await
    }

    pub(crate) fn validate_body_length(&self, body_length: usize) -> Result<(), AdmissionError> {
        self.lease.validate_body_length(body_length)
    }
}

impl OperationRouter {
    /// Binds a service identity to the shared upstream manager.
    pub(crate) const fn new(manager: Arc<UpstreamManager>, service: PolicyService) -> Self {
        Self { manager, service }
    }

    pub(crate) fn capture_request(&self, operation: OperationKind) -> RequestRouting {
        RequestRouting {
            manager: Arc::clone(&self.manager),
            lease: self.manager.capture_request(self.service, operation),
        }
    }

    /// Records a successful request and completes a recovery trial when present.
    pub(crate) async fn note_success(&self, bound_server: &BoundServer) {
        self.manager.note_bound_server_success(bound_server).await;
    }

    /// Records a request failure and moves the operation cursor when needed.
    pub(crate) async fn note_failure(&self, bound_server: &BoundServer) {
        self.manager.note_bound_server_failure(bound_server).await;
    }
}
