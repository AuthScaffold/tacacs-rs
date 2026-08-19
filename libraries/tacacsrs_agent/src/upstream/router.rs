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
use super::failover::FailoverPlan;
use super::manager::{BoundServer, UpstreamManager};
use super::operation::OperationKind;

/// Routing and admission entry point for one local service.
#[derive(Clone)]
pub(crate) struct OperationRouter {
    manager: Arc<UpstreamManager>,
    service: PolicyService,
}

impl OperationRouter {
    /// Binds a service identity to the shared upstream manager.
    pub(crate) const fn new(manager: Arc<UpstreamManager>, service: PolicyService) -> Self {
        Self { manager, service }
    }

    /// Waits for shared operation capacity and validates the request size.
    ///
    /// # Errors
    ///
    /// Returns an error if the body exceeds the configured operation limit or
    /// no capacity became available within the upstream server timeout.
    pub(crate) async fn admit(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.manager.admit_request(operation, body_length).await
    }

    /// Validates one packet body without acquiring another concurrency permit.
    ///
    /// # Errors
    ///
    /// Returns an error if the body exceeds the configured operation limit.
    pub(crate) fn validate_body_length(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<(), AdmissionError> {
        self.manager.validate_request_size(operation, body_length)
    }

    /// Builds the retry plan for one request of this service.
    pub(crate) fn failover_plan(&self, operation: OperationKind) -> FailoverPlan {
        self.manager.failover_plan(self.service, operation)
    }

    /// Selects an eligible server and its operation-scoped connection.
    ///
    /// # Errors
    ///
    /// Returns an error if no configured server supports the operation or no
    /// eligible server accepted a connection.
    pub(crate) async fn bind(&self, operation: OperationKind) -> anyhow::Result<BoundServer> {
        self.manager.bind_server_for_operation(operation).await
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
