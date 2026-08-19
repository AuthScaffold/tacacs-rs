//! Immutable configured server snapshots used by routing decisions.

use std::sync::Arc;
use std::time::Duration;

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tokio::sync::RwLock;

use super::server_slot::ServerSlot;
use super::circuit::RecoveryPermit;
use crate::config::{ProxyDownstreamObfuscation, RuntimePolicy};
use crate::upstream::admission::AdmissionRegistry;
use crate::upstream::{OperationKind, UpstreamConnection};

/// Immutable routing inputs published as one generation.
pub(super) struct RuntimeRoutingSnapshot {
    pub(super) server_set: Arc<ServerSet>,
    pub(super) proxy_downstream_obfuscation: ProxyDownstreamObfuscation,
    pub(super) runtime_policy: Arc<RuntimePolicy>,
    pub(super) admission: Arc<AdmissionRegistry>,
}

/// Immutable server set and its mutable failover cursor.
pub(super) struct ServerSet {
    /// Per-server state including cached connections and reconnect locks.
    pub(super) servers: Vec<Arc<ServerSlot>>,
    /// Independent eligible-server lists and cursors for each operation.
    routes: [OperationRoute; 3],
}

/// Ordered eligible servers and the active position for one operation.
pub(super) struct OperationRoute {
    server_indices: Vec<usize>,
    active_position: RwLock<usize>,
}

/// Result of binding an IPC request to a TACACS+ server.
///
/// Contains the server index for failover records and the request connection.
pub(crate) struct BoundServer {
    /// The server snapshot this request was bound against.
    pub(super) server_set: Arc<ServerSet>,
    /// Index in the service server list.
    pub(crate) index: usize,
    /// Operation that owns this connection and route decision.
    pub(crate) operation: OperationKind,
    /// Connection generation used to prevent stale failure invalidation.
    pub(super) connection_generation: u64,
    /// Present when this request owns the one half-open recovery trial.
    pub(super) recovery_permit: Option<RecoveryPermit>,
    /// Server connection for this request.
    pub(crate) connection: Arc<dyn UpstreamConnection>,
}

impl BoundServer {
    /// Returns the configured upstream server selected for this request.
    pub(crate) fn server(&self) -> &TacacsPlusServer {
        &self.server_set.servers[self.index].server
    }

    /// Returns the timeout configured on the selected upstream server.
    pub(crate) fn timeout_duration(&self) -> Duration {
        self.server().timeout_duration()
    }
}

impl ServerSet {
    pub(super) fn new(servers: Vec<Arc<ServerSlot>>) -> Self {
        let routes = OperationKind::ALL.map(|operation| {
            let server_indices = servers
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| {
                    slot.server
                        .supports_server_type(operation.server_type())
                        .then_some(index)
                })
                .collect();
            OperationRoute {
                server_indices,
                active_position: RwLock::new(0),
            }
        });
        Self { servers, routes }
    }

    pub(super) fn server_count(&self) -> usize {
        self.servers.len()
    }

    pub(super) fn route(&self, operation: OperationKind) -> &OperationRoute {
        &self.routes[operation.index()]
    }
}

impl OperationRoute {
    pub(super) fn server_count(&self) -> usize {
        self.server_indices.len()
    }

    pub(super) fn server_index(&self, position: usize) -> usize {
        self.server_indices[position]
    }

    pub(super) async fn active_position(&self) -> usize {
        *self.active_position.read().await
    }

    pub(super) async fn set_active_position(&self, position: usize) {
        *self.active_position.write().await = position;
    }

    pub(super) fn position_of(&self, server_index: usize) -> Option<usize> {
        self.server_indices
            .iter()
            .position(|index| *index == server_index)
    }

    pub(super) async fn active_server_name(&self, servers: &[Arc<ServerSlot>]) -> Option<String> {
        if self.server_indices.is_empty() {
            return None;
        }
        let position = self.active_position().await;
        Some(servers[self.server_indices[position]].name().to_owned())
    }

    pub(super) async fn preserve_active_server(
        &self,
        previous_name: Option<&str>,
        servers: &[Arc<ServerSlot>],
    ) {
        let position = previous_name
            .and_then(|name| {
                self.server_indices
                    .iter()
                    .position(|index| servers[*index].name() == name)
            })
            .unwrap_or(0);
        self.set_active_position(position).await;
    }

    pub(super) async fn advance_if_active(
        &self,
        failed_server_index: usize,
    ) -> Option<(usize, usize)> {
        if self.server_indices.is_empty() {
            return None;
        }
        let mut active = self.active_position.write().await;
        if self.server_indices[*active] != failed_server_index {
            return None;
        }
        let previous = self.server_indices[*active];
        *active = (*active + 1) % self.server_indices.len();
        Some((previous, self.server_indices[*active]))
    }
}
