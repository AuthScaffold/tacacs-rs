//! Per-server upstream connection cache and reconnect serialization.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tokio::sync::{Mutex, RwLock};

use crate::upstream::UpstreamConnection;

/// Per-server cached connection state.
///
/// Each configured TACACS+ server gets its own `ServerSlot` so reconnect
/// serialization and connection caching are independent.
pub(super) struct ServerSlot {
    /// The per-server connection configuration.
    pub(super) server: Arc<TacacsPlusServer>,
    /// Cached upstream connection, if any. `None` means the server needs a
    /// fresh connection on the next request.
    pub(super) connection: RwLock<Option<Arc<dyn UpstreamConnection>>>,
    /// Lock that serializes reconnect attempts for this server.
    pub(super) connect_lock: Mutex<()>,
    /// Monotonically increasing counter of completed connect attempts.
    /// Used to detect when another task has already reconnected while this task
    /// was waiting for the lock.
    pub(super) completed_connect_attempts: AtomicU64,
}

impl ServerSlot {
    pub(super) fn new(server: Arc<TacacsPlusServer>) -> Self {
        Self {
            server,
            connection: RwLock::new(None),
            connect_lock: Mutex::new(()),
            completed_connect_attempts: AtomicU64::new(0),
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

    pub(super) async fn drain_cached_connection(&self) {
        let connection = self.connection.write().await.take();
        if let Some(connection) = connection {
            log::debug!(
                "Draining cached upstream connection for {} during configuration reload",
                self.server.socket_address(),
            );
            connection.stop_accepting_new_sessions().await;
        }
    }
}
