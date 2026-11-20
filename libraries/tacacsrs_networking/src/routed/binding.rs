//! Captured endpoint bindings and generation-fenced upstream outcome reports.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::{Endpoint, EndpointConnector, NativeConnector, OperationKind, RoutedClient};
use super::catalog::CachedConnection;
use super::circuit::RecoveryPermit;
use super::client::FailureKind;

/// How a binding with an open circuit can close that circuit.
pub(super) enum RecoveryClaim {
    Trial(RecoveryPermit),
    LastResort(u64),
}

struct BindingReport {
    reported: AtomicBool,
    revision: AtomicU64,
}

/// Reports an upstream attempt that its deadline interrupted.
///
/// Call [`Self::disarm`] after a valid reply or a local validation failure.
/// Call [`Self::fail`] after an upstream I/O failure.
///
/// Dropping an armed observation after its deadline records a server timeout.
/// Dropping it before its deadline records nothing, because caller cancellation
/// does not prove that the server failed. Arm it only during upstream I/O.
///
/// Each binding records at most one failure. The first report from the
/// binding or any of its observations decides the effect. Reports update the
/// captured connection generation synchronously. The endpoint lifecycle owns
/// connection retirement.
pub struct FailureObservation<Connector: EndpointConnector> {
    client: RoutedClient<Connector>,
    index: usize,
    operation: OperationKind,
    generation: u64,
    report: Arc<BindingReport>,
    deadline: crate::RequestDeadline,
    armed: bool,
}

impl<Connector: EndpointConnector> FailureObservation<Connector> {
    /// Marks a valid response or local validation failure as non-interrupted.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Records an upstream I/O failure now.
    ///
    /// The failure detaches the shared connection. If the connection completed
    /// a valid exchange and the deadline has not expired, the next binding
    /// reconnects to the same endpoint. Otherwise, the failure also opens the
    /// circuit for this operation.
    pub fn fail(mut self) {
        self.armed = false;
        let kind = if self.deadline.check().is_err() {
            FailureKind::Server
        } else {
            FailureKind::Transport
        };
        self.record_failure(kind);
    }

    fn record_failure(&self, kind: FailureKind) {
        if self.report.reported.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(connection) = self.client.invalidate_failure(
            self.index,
            self.operation,
            self.generation,
            kind,
            self.report.revision.load(Ordering::Acquire),
        ) {
            self.client.catalog.endpoints[self.index]
                .lifecycle
                .retire_detached(connection);
        }
    }
}

impl<Connector: EndpointConnector> Drop for FailureObservation<Connector> {
    fn drop(&mut self) {
        if self.armed && self.deadline.check().is_err() {
            self.record_failure(FailureKind::Server);
        }
    }
}

/// Connection and outcome-reporting identity for one selected endpoint.
///
/// The client retains the shared connection while any binding holds it.
pub struct BoundEndpoint<Connector: EndpointConnector = NativeConnector> {
    client: RoutedClient<Connector>,
    index: usize,
    operation: OperationKind,
    cached: CachedConnection<Connector::Connection>,
    recovery: Option<RecoveryClaim>,
    report: Arc<BindingReport>,
}

impl<Connector: EndpointConnector> BoundEndpoint<Connector> {
    pub(super) fn new(
        client: RoutedClient<Connector>,
        index: usize,
        operation: OperationKind,
        cached: CachedConnection<Connector::Connection>,
        recovery: Option<RecoveryClaim>,
        revision: u64,
    ) -> Self {
        Self {
            client,
            index,
            operation,
            cached,
            recovery,
            report: Arc::new(BindingReport {
                reported: AtomicBool::new(false),
                revision: AtomicU64::new(revision),
            }),
        }
    }

    /// Arms failure reporting with the deadline that bounds upstream I/O.
    ///
    /// Do not keep the observation armed during downstream waits.
    #[must_use]
    pub fn observe_failure(
        &self,
        deadline: crate::RequestDeadline,
    ) -> FailureObservation<Connector> {
        FailureObservation {
            client: self.client.clone(),
            index: self.index,
            operation: self.operation,
            generation: self.cached.generation,
            report: Arc::clone(&self.report),
            deadline,
            armed: true,
        }
    }

    /// Returns the selected prepared endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.client.catalog.endpoints[self.index].endpoint
    }

    /// Returns the selected endpoint's catalog position.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Borrows the shared connection handle used to execute an exchange.
    #[must_use]
    pub fn connection(&self) -> &Arc<Connector::Connection> {
        &self.cached.connection
    }

    /// Returns the connection attempt identity for diagnostics.
    #[must_use]
    pub const fn connection_generation(&self) -> u64 {
        self.cached.generation
    }

    /// Records an upstream `ERROR` or a server timeout.
    ///
    /// The failure opens the circuit for this endpoint and operation, and
    /// advances its active route. Other operations retain the shared
    /// connection. Report transport errors through [`FailureObservation::fail`].
    ///
    /// Invalidation completes without yielding. The endpoint lifecycle owns
    /// retirement, which cannot extend the request deadline.
    #[allow(
        clippy::unused_async,
        reason = "Retain the async reporting API while committing failure state without yielding."
    )]
    pub async fn note_server_failure(&self) {
        if self.report.reported.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(connection) = self.client.invalidate_failure(
            self.index,
            self.operation,
            self.cached.generation,
            FailureKind::Server,
            self.report.revision.load(Ordering::Acquire),
        ) {
            self.client.catalog.endpoints[self.index]
                .lifecycle
                .retire_detached(connection);
        }
    }

    /// Records a valid exchange on this connection.
    ///
    /// A later I/O failure reconnects to the same endpoint. A success on a
    /// recovery trial or last-resort binding also closes the circuit. If this
    /// endpoint becomes active, the client retires unused alternatives.
    #[allow(
        clippy::unused_async,
        reason = "Retain the async reporting API while committing success state without yielding."
    )]
    pub async fn note_success(&self) {
        let slot = &self.client.catalog.endpoints[self.index];
        let circuit = &slot.operation(self.operation).circuit;
        let closed = {
            let cache = slot
                .connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.cached.generation != slot.connection_generation.load(Ordering::Acquire)
                || cache
                    .as_ref()
                    .is_none_or(|cached| cached.generation != self.cached.generation)
            {
                return;
            }
            slot.proven_generation
                .store(self.cached.generation, Ordering::Release);
            match &self.recovery {
                None => false,
                Some(RecoveryClaim::Trial(permit)) => permit.succeed(),
                Some(RecoveryClaim::LastResort(revision)) => circuit.close_if_unchanged(*revision),
            }
        };
        if closed {
            self.report
                .revision
                .store(circuit.revision(), Ordering::Release);
            self.client.promote_recovered(self.index, self.operation);
        }
    }
}

impl<Connector: EndpointConnector> Drop for BoundEndpoint<Connector> {
    fn drop(&mut self) {
        let slot = &self.client.catalog.endpoints[self.index];
        let previous = {
            let _cache = slot
                .connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slot.bindings.fetch_sub(1, Ordering::AcqRel)
        };
        if previous == 1 {
            self.client.retire_if_unused(self.index);
        }
    }
}
