//! Immutable configured server snapshots used by routing decisions.

use std::sync::Arc;

use tacacsrs_config::TacacsPlusServer;
use tokio::sync::RwLock;

use super::server_slot::ServerSlot;
use crate::upstream::UpstreamConnection;

/// Immutable configured server snapshot plus its mutable failover cursor.
pub(super) struct ServerSet {
    /// Per-server state including cached connections and reconnect locks.
    pub(super) servers: Vec<Arc<ServerSlot>>,
    /// Index into `servers` of the currently preferred server for new sessions.
    pub(super) active_index: RwLock<usize>,
}

/// The result of binding an IPC request to an upstream server.
///
/// Contains both the server index for recording failover and the connection
/// handle used to execute the request.
pub(crate) struct BoundServer {
    /// The server snapshot this request was bound against.
    pub(super) server_set: Arc<ServerSet>,
    /// Index into the service's server list.
    pub(crate) index: usize,
    /// The upstream connection to use for this request.
    pub(crate) connection: Arc<dyn UpstreamConnection>,
}

impl ServerSet {
    pub(super) fn new(servers: Vec<Arc<ServerSlot>>, active_index: usize) -> Self {
        Self {
            servers,
            active_index: RwLock::new(active_index),
        }
    }

    pub(super) fn server_count(&self) -> usize {
        self.servers.len()
    }
}

pub(super) fn servers_equivalent(left: &TacacsPlusServer, right: &TacacsPlusServer) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
