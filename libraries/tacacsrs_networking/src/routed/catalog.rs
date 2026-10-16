//! Catalog scope: endpoint identity and operation-scoped routing state.
//!
//! A [`Catalog`] is the per-publication routing table a
//! [`RoutedClient`](super::RoutedClient) captures. It maps each eligible
//! [`Endpoint`] to per-operation slots that cache a connection and track circuit
//! state:
//!
//! ```text
//! Catalog
//!   -> EndpointSlot    (one per endpoint, keyed by cloned Endpoint identity)
//!        -> OperationSlot    (one per operation kind)
//!             -> CachedConnection    (reused until reconnect or retirement)
//! ```
//!
//! [`Endpoint`] identity is an opaque `Arc`: cloning reuses a cache slot across
//! replacement catalogs, while a fresh identity resets the cached connection and
//! circuit. The catalog does not own transport lifetime directly; the
//! [`lifecycle`](super::lifecycle) module owns setup and retirement, and the
//! [`connection`](crate::connection) runtimes own packet I/O.

use std::sync::{Arc, Mutex as StateMutex};
use std::sync::atomic::AtomicU64;

use tokio::sync::Mutex;

use crate::PreparedEndpoint;

use super::OperationKind;
use super::EndpointConnector;
use super::lifecycle::EndpointLifecycle;
use super::circuit::OperationCircuit;

/// Prepared endpoint identity and explicit operation eligibility.
///
/// Cloning preserves identity for cache reuse across catalogs. Construct a new
/// value when credentials, transport settings, or eligibility change.
#[derive(Clone)]
pub struct Endpoint {
    inputs: Arc<EndpointInputs>,
}

struct EndpointInputs {
    name: String,
    prepared: PreparedEndpoint,
    operations: [bool; 3],
}

impl Endpoint {
    /// Creates an endpoint without I/O or source configuration access.
    pub fn new(
        name: impl Into<String>,
        prepared: PreparedEndpoint,
        operations: impl IntoIterator<Item = OperationKind>,
    ) -> Self {
        let mut eligible = [false; 3];
        for operation in operations {
            eligible[operation.index()] = true;
        }
        Self {
            inputs: Arc::new(EndpointInputs {
                name: name.into(),
                prepared,
                operations: eligible,
            }),
        }
    }

    /// Returns the caller-assigned endpoint name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inputs.name
    }

    /// Returns the immutable prepared transport inputs.
    #[must_use]
    pub fn prepared(&self) -> &PreparedEndpoint {
        &self.inputs.prepared
    }

    /// Returns whether this endpoint supports the operation.
    #[must_use]
    pub fn supports(&self, operation: OperationKind) -> bool {
        self.inputs.operations[operation.index()]
    }

    pub(super) fn same_identity(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inputs, &other.inputs)
    }
}

pub(super) struct CachedConnection<Connection: ?Sized> {
    pub(super) generation: u64,
    pub(super) connection: Arc<Connection>,
}

pub(super) struct OperationSlot<Connection: ?Sized> {
    pub(super) connection: StateMutex<Option<CachedConnection<Connection>>>,
    pub(super) connect_lock: Mutex<()>,
    pub(super) completed_connect_attempts: AtomicU64,
    pub(super) connection_generation: AtomicU64,
    pub(super) failed_generation: AtomicU64,
    pub(super) circuit: Arc<OperationCircuit>,
}

impl<Connection: ?Sized> Default for OperationSlot<Connection> {
    fn default() -> Self {
        Self {
            connection: StateMutex::new(None),
            connect_lock: Mutex::new(()),
            completed_connect_attempts: AtomicU64::new(0),
            connection_generation: AtomicU64::new(0),
            failed_generation: AtomicU64::new(u64::MAX),
            circuit: Arc::new(OperationCircuit::default()),
        }
    }
}

pub(super) struct EndpointSlot<Connector: EndpointConnector> {
    pub(super) endpoint: Endpoint,
    pub(super) operations: [OperationSlot<Connector::Connection>; 3],
    pub(super) lifecycle: Arc<EndpointLifecycle<Connector>>,
}

impl<Connector: EndpointConnector> EndpointSlot<Connector> {
    pub(super) fn new(endpoint: Endpoint, lifecycle: Arc<EndpointLifecycle<Connector>>) -> Self {
        Self {
            endpoint,
            lifecycle,
            operations: std::array::from_fn(|_| OperationSlot::default()),
        }
    }

    pub(super) fn operation(
        &self,
        operation: OperationKind,
    ) -> &OperationSlot<Connector::Connection> {
        &self.operations[operation.index()]
    }
}

pub(super) struct Catalog<Connector: EndpointConnector> {
    pub(super) endpoints: Vec<Arc<EndpointSlot<Connector>>>,
    routes: [OperationRoute; 3],
}

impl<Connector: EndpointConnector> Catalog<Connector> {
    pub(super) fn new(endpoints: Vec<Arc<EndpointSlot<Connector>>>) -> Self {
        let routes = OperationKind::ALL.map(|operation| OperationRoute {
            indices: endpoints
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.endpoint.supports(operation).then_some(index))
                .collect(),
            active_position: StateMutex::new(0),
        });
        Self { endpoints, routes }
    }

    pub(super) fn route(&self, operation: OperationKind) -> &OperationRoute {
        &self.routes[operation.index()]
    }
}

pub(super) struct OperationRoute {
    pub(super) indices: Vec<usize>,
    pub(super) active_position: StateMutex<usize>,
}

impl OperationRoute {
    pub(super) fn advance_if_active(&self, failed_index: usize) {
        if self.indices.is_empty() {
            return;
        }
        let mut active = self
            .active_position
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.indices[*active] == failed_index {
            *active = (*active + 1) % self.indices.len();
        }
    }
}
