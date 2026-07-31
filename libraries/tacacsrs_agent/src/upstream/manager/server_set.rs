//! Immutable configured server snapshots used by routing decisions.

use std::sync::Arc;
use std::time::Duration;

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
#[cfg(test)]
use tacacsrs_credential_resolution::RuntimeServer;
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

impl BoundServer {
    /// Returns the configured upstream server selected for this request.
    pub(crate) fn server(&self) -> &TacacsPlusServer {
        self.server_set.servers[self.index].server.config()
    }

    #[cfg(test)]
    pub(crate) fn runtime_server(&self) -> &RuntimeServer {
        &self.server_set.servers[self.index].server
    }

    /// Returns the timeout configured on the selected upstream server.
    pub(crate) fn timeout_duration(&self) -> Duration {
        self.server().timeout_duration()
    }
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
