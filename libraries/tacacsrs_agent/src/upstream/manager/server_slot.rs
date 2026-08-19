//! Per-server connection cache and reconnect serialization.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tokio::sync::{Mutex, RwLock};

use super::circuit::OperationCircuit;
use crate::upstream::UpstreamConnection;
use crate::upstream::OperationKind;

/// Cached connection state for one operation on one server.
pub(super) struct OperationSlot {
    /// Cached operation-scoped server connection.
    pub(super) connection: RwLock<Option<Arc<dyn UpstreamConnection>>>,
    /// Lock that serializes reconnect attempts for this operation.
    pub(super) connect_lock: Mutex<()>,
    /// Increasing count of completed connection attempts.
    pub(super) completed_connect_attempts: AtomicU64,
    /// Shared circuit state for this server operation.
    pub(super) circuit: Arc<OperationCircuit>,
}

impl OperationSlot {
    fn new() -> Self {
        Self {
            connection: RwLock::new(None),
            connect_lock: Mutex::new(()),
            completed_connect_attempts: AtomicU64::new(0),
            circuit: Arc::new(OperationCircuit::default()),
        }
    }
}

/// Per-server cached connection state.
///
/// Each configured TACACS+ server has one `ServerSlot`. Each slot has an
/// independent connection cache and reconnect lock.
pub(super) struct ServerSlot {
    /// Connection configuration for this server.
    pub(super) server: Arc<TacacsPlusServer>,
    /// Independent connection state for each TACACS+ operation.
    operations: [OperationSlot; 3],
}

impl ServerSlot {
    pub(super) fn new(server: Arc<TacacsPlusServer>) -> Self {
        Self {
            server,
            operations: std::array::from_fn(|_| OperationSlot::new()),
        }
    }

    pub(super) fn config(&self) -> &TacacsPlusServer {
        &self.server
    }

    pub(super) fn name(&self) -> &str {
        &self.config().name
    }

    pub(super) fn socket_address(&self) -> String {
        self.config().socket_address()
    }

    pub(super) fn operation(&self, operation: OperationKind) -> &OperationSlot {
        &self.operations[operation.index()]
    }

    pub(super) async fn drain_cached_connection(&self) {
        for operation in OperationKind::ALL {
            let connection = self.operation(operation).connection.write().await.take();
            if let Some(connection) = connection {
                log::debug!(
                    "Draining cached {} connection for {} during configuration reload",
                    operation.name(),
                    self.server.socket_address(),
                );
                connection.stop_accepting_new_sessions().await;
            }
        }
    }
}
