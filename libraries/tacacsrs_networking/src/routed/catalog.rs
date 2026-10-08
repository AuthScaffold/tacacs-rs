//! Immutable endpoint inputs and operation-scoped routing state.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tokio::sync::{Mutex, RwLock};

use crate::PreparedEndpoint;

use super::OperationKind;
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
    pub(super) connection: RwLock<Option<CachedConnection<Connection>>>,
    pub(super) connect_lock: Mutex<()>,
    pub(super) completed_connect_attempts: AtomicU64,
    pub(super) circuit: Arc<OperationCircuit>,
}

impl<Connection: ?Sized> Default for OperationSlot<Connection> {
    fn default() -> Self {
        Self {
            connection: RwLock::new(None),
            connect_lock: Mutex::new(()),
            completed_connect_attempts: AtomicU64::new(0),
            circuit: Arc::new(OperationCircuit::default()),
        }
    }
}

pub(super) struct EndpointSlot<Connection: ?Sized> {
    pub(super) endpoint: Endpoint,
    pub(super) operations: [OperationSlot<Connection>; 3],
}

impl<Connection: ?Sized> EndpointSlot<Connection> {
    pub(super) fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            operations: std::array::from_fn(|_| OperationSlot::default()),
        }
    }

    pub(super) fn operation(&self, operation: OperationKind) -> &OperationSlot<Connection> {
        &self.operations[operation.index()]
    }
}

pub(super) struct Catalog<Connection: ?Sized> {
    pub(super) endpoints: Vec<Arc<EndpointSlot<Connection>>>,
    routes: [OperationRoute; 3],
}

impl<Connection: ?Sized> Catalog<Connection> {
    pub(super) fn new(endpoints: Vec<Arc<EndpointSlot<Connection>>>) -> Self {
        let routes = OperationKind::ALL.map(|operation| OperationRoute {
            indices: endpoints
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.endpoint.supports(operation).then_some(index))
                .collect(),
            active_position: RwLock::new(0),
        });
        Self { endpoints, routes }
    }

    pub(super) fn route(&self, operation: OperationKind) -> &OperationRoute {
        &self.routes[operation.index()]
    }
}

pub(super) struct OperationRoute {
    pub(super) indices: Vec<usize>,
    pub(super) active_position: RwLock<usize>,
}

impl OperationRoute {
    pub(super) async fn advance_if_active(&self, failed_index: usize) {
        if self.indices.is_empty() {
            return;
        }
        let mut active = self.active_position.write().await;
        if self.indices[*active] == failed_index {
            *active = (*active + 1) % self.indices.len();
        }
    }
}
