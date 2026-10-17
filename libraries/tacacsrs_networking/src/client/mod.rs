//! Client scope: TACACS+ transport setup and the dedicated-to-shared transition.
//!
//! [`TacacsClient`] is the client facade. It owns transport establishment, the
//! single-connection capability transition, and terminal shutdown. Callers run
//! typed request/reply descriptors with [`TacacsClient::execute`] or open a
//! mutable packet [`ClientConversation`](crate::session::ClientConversation) for
//! transparent proxying.
//!
//! # Module layout
//!
//! Client responsibilities are split across private submodules so each file owns
//! one concern:
//!
//! - [`selection`]: session selection and the single-connection state machine.
//! - [`exchange`]: fixed request/reply execution and reply-header validation.
//! - [`preflight`]: the configured connection preflight and discovery probe.
//! - [`lifecycle`]: terminal state, setup ownership, and transport lifetimes.
//!
//! # Scope boundaries
//!
//! The client holds the shared-connection cache and the single-connection state
//! as capabilities. It never reaches into the cache slot, epoch, or closed flag;
//! the [`single_connect`](crate::single_connect) module owns those fields and the
//! publication fence. The [`connection`](crate::connection) module owns the
//! packet runtimes a session drives, and the [`session`](crate::session) module
//! hides whether an operation uses a dedicated or shared transport.
//!
//! # Lifecycle
//!
//! [`TacacsClient::close`] permanently rejects new work.
//! [`TacacsClient::close_and_join`] drains existing sessions until its deadline,
//! then forces transport closure and joins owned tasks. Dropping the client
//! requests immediate cleanup; retained conversations do not extend its transport
//! lifetime.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::endpoint::PreparedEndpoint;
use crate::single_connect::{NegotiationState, SharedConnectionCache, SingleConnectionState};

mod exchange;
mod lifecycle;
mod preflight;
mod selection;

#[cfg(test)]
mod tests;

use lifecycle::ClientLifecycle;

/// A configured TACACS+ client that selects a dedicated or shared connection.
///
/// When the server configuration enables single-connection mode, the first
/// operation uses the configured preflight or a dedicated session to ask
/// the server for single-connection support. If the server echoes the
/// single-connect flag, the client upgrades and caches that connection for future
/// sessions. If single-connection mode is disabled in configuration or
/// unsupported by the server, future operations continue to use dedicated
/// connections.
///
/// [`Self::close`] permanently rejects new work. [`Self::close_and_join`]
/// drains existing sessions until its deadline, then forces transport closure
/// and joins owned tasks. Dropping the client requests immediate cleanup;
/// retained conversations do not extend the client's transport lifetime.
pub struct TacacsClient {
    endpoint: PreparedEndpoint,
    lifecycle: Arc<ClientLifecycle>,
    shared_connection: Arc<SharedConnectionCache>,
    single_connection_state: Arc<NegotiationState>,
    /// Serializes recovery when the cached shared connection is not available.
    ///
    /// The normal shared-session path does not take this lock. It only protects
    /// the slow path so concurrent callers do not all open probe
    /// connections after the same shared connection disconnects.
    shared_recovery_lock: Mutex<()>,
}

impl Drop for TacacsClient {
    fn drop(&mut self) {
        self.close();
        self.lifecycle.force_close_transports();
    }
}

impl TacacsClient {
    /// Creates a client without opening a network connection.
    fn from_prepared(endpoint: PreparedEndpoint) -> Self {
        let single_connection_enabled = endpoint.single_connection();
        Self {
            endpoint,
            lifecycle: Arc::default(),
            shared_connection: Arc::default(),
            single_connection_state: Arc::new(NegotiationState::new(
                if single_connection_enabled {
                    SingleConnectionState::Initial
                } else {
                    SingleConnectionState::NotSupported
                },
            )),
            shared_recovery_lock: Mutex::new(()),
        }
    }

    /// Creates a client and optionally performs the configured preflight.
    ///
    /// When accounting watchdog preflight is enabled and the server
    /// configuration requests single-connection mode, the preflight request also
    /// performs capability discovery. A server that echoes the single-connect
    /// flag promotes the preflight transport into the cached shared connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the local certificate expired or the configured preflight fails.
    pub async fn connect_prepared(endpoint: PreparedEndpoint) -> anyhow::Result<Self> {
        if let Some(lifetime) = endpoint.prepared_credential_lifetime() {
            lifetime.check()?;
        }
        let connection = Self::from_prepared(endpoint);
        connection.run_preflight().await?;
        Ok(connection)
    }

    /// Stops the cached shared connection from accepting new sessions.
    ///
    /// Dedicated sessions are opened per operation and have no cached state to
    /// drain. If a shared connection exists, it is removed from the cache and told
    /// to reject future session creation while already-created sessions finish.
    pub async fn stop_accepting_new_sessions(&self) {
        self.shared_connection.stop_accepting_new_sessions().await;
    }

    /// Permanently rejects new work and cancels in-progress connection setup.
    ///
    /// Existing sessions can finish until [`Self::close_and_join`] forces cleanup.
    /// Closing is idempotent. A closed client cannot be reopened.
    pub fn close(&self) {
        self.lifecycle.close();
        self.shared_connection.mark_closed();
    }

    /// Closes the client, drains sessions, and joins setup, driver, and certificate-expiry tasks.
    ///
    /// At `deadline`, remaining transports close even if callers retain idle
    /// conversations or do not poll their I/O futures. Cancelled joins can be retried;
    /// the client remains closed. Final client drop also requests immediate cleanup.
    /// Certificate expiry can close a transport before this shutdown deadline.
    ///
    /// # Errors
    /// Returns a setup or driver task failure after completing other cleanup.
    /// This can include an I/O error from a driver already stopped by certificate expiry.
    pub async fn close_and_join(&self, deadline: crate::RequestDeadline) -> anyhow::Result<()> {
        self.close();
        self.stop_accepting_new_sessions().await;
        let setup_result = self.lifecycle.join_setups(deadline).await;
        let _drained = deadline.run(self.lifecycle.wait_for_transports()).await;
        let driver_result = self.retire_shared_until(deadline).await;
        self.lifecycle.force_close_transports();
        self.lifecycle.wait_for_transports().await;
        let expiry_result = self.lifecycle.join_expiries(deadline).await;
        setup_result.and(driver_result).and(expiry_result)
    }

    /// Retires and joins the currently cached and previously retired shared drivers.
    ///
    /// New sessions on those connections are disabled. Active sessions can drain
    /// until `deadline`; expiry aborts the drivers and waits for their cleanup.
    /// Cancellation retains the driver handles, so this method can be retried.
    ///
    /// This is shared-connection retirement, not client shutdown. Dedicated
    /// sessions and new session creation through this client remain permitted.
    /// The caller must quiesce new operations when using this as a shutdown step.
    /// Negotiations captured before retirement cannot repopulate the shared cache.
    ///
    /// # Errors
    /// Returns a driver I/O error or task failure after joining its task.
    pub async fn retire_shared_until(
        &self,
        deadline: crate::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.shared_connection.stop_accepting_new_sessions().await;
        self.shared_connection.retire_all_until(deadline).await
    }
}
