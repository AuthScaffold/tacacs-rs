//! Per-service view over the shared upstream manager.
//!
//! [`UpstreamManager`] holds state for every local service. A service must not
//! see all of it. [`OperationRouter`] binds one [`PolicyService`] identity at
//! construction and captures immutable request inputs. [`RequestRouting`] uses
//! its lease for admission and its manager for binding and availability updates.
//! [`BoundServer`] records outcomes through the networking binding.
//!
//! This keeps `PolicyService` out of every call site and stops a service from
//! reading state that belongs to another service.

use std::sync::Arc;

use crate::config::PolicyService;

use super::admission::{AdmissionError, AdmissionPermit};
use tacacsrs_networking::retry::FailoverPlan;
use tacacsrs_networking::routed::EndpointConnector;
use super::manager::{BoundServer, RoutingLease, UpstreamManager};
use super::OperationKind;

/// Routing and admission entry point for one local service.
pub(crate) struct OperationRouter<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    manager: Arc<UpstreamManager<Connector>>,
    service: PolicyService,
}

/// Captures one request's routing inputs across all of its attempts.
pub(crate) struct RequestRouting<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    manager: Arc<UpstreamManager<Connector>>,
    lease: RoutingLease<Connector>,
}

impl<Connector: EndpointConnector> Clone for OperationRouter<Connector> {
    fn clone(&self) -> Self {
        Self {
            manager: self.manager.clone(),
            service: self.service,
        }
    }
}

impl<Connector: EndpointConnector> RequestRouting<Connector> {
    pub(crate) fn generation(&self) -> u64 {
        self.lease.generation()
    }

    pub(crate) fn reserve(
        &self,
        body_length: usize,
    ) -> Result<tacacsrs_networking::admission::AdmissionReservation, AdmissionError> {
        self.lease.reserve(body_length)
    }

    pub(crate) async fn admit_reserved(
        &self,
        reservation: tacacsrs_networking::admission::AdmissionReservation,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.lease.admit_reserved(reservation).await
    }

    pub(crate) fn deadline(&self) -> tacacsrs_networking::RequestDeadline {
        self.lease.deadline()
    }

    pub(crate) fn failover_plan(&self) -> FailoverPlan {
        self.lease.failover_plan()
    }

    pub(crate) async fn bind(&self) -> anyhow::Result<BoundServer<Connector>> {
        self.manager.bind_request(&self.lease).await
    }

    pub(crate) async fn admit(
        &self,
        body_length: usize,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.lease.admit(body_length).await
    }

    pub(crate) fn validate_body_length(&self, body_length: usize) -> Result<(), AdmissionError> {
        self.lease.validate_body_length(body_length)
    }
}

impl<Connector: EndpointConnector> OperationRouter<Connector> {
    /// Binds a service identity to the shared upstream manager.
    pub(crate) const fn new(
        manager: Arc<UpstreamManager<Connector>>,
        service: PolicyService,
    ) -> Self {
        Self { manager, service }
    }

    pub(crate) fn capture_request(&self, operation: OperationKind) -> RequestRouting<Connector> {
        RequestRouting {
            manager: Arc::clone(&self.manager),
            lease: self.manager.capture_request(self.service, operation),
        }
    }
}
