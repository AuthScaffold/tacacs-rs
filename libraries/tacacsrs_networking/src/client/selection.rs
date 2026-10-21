//! Session selection and the TACACS+ single-connection state machine.
//!
//! These [`TacacsClient`] methods choose a dedicated or shared session for each
//! operation and drive the single-connection capability state. The client holds
//! the shared-connection cache as a capability; the
//! [`single_connect`](crate::single_connect) module owns the cache slot, epoch,
//! closed flag, and the publication fence.

use std::sync::Arc;

use crate::connection::MultiplexedConnection;
use crate::session::{ClientConversation, ClientSession, DedicatedSession, ExpectedResponseHeader};
use crate::single_connect::{SingleConnectPromotion, SingleConnectionState};
use crate::transport::BoxedTransport;

use super::TacacsClient;

impl TacacsClient {
    /// Creates a client session suitable for running TACACS+ flows.
    ///
    /// Session selection uses the server configuration and the observed
    /// single-connection state:
    ///
    /// ```text
    /// server.single_connection = false
    ///     |
    ///     v
    /// fresh dedicated session without single-connect flag
    ///
    /// server.single_connection = true
    ///     |
    ///     v
    /// accounting watchdog preflight, when enabled
    ///     |
    ///     +-- server echoes flag --------> [Supported]
    ///     |                                  |
    ///     |                                  v
    ///     |                         first create_session uses
    ///     |                         cached shared connection
    ///     |
    ///     +-- server omits flag ---------> [NotSupported]
    ///                                        |
    ///                                        v
    ///                              dedicated sessions only
    ///
    /// preflight disabled or shared recovery
    ///     |
    ///     v
    /// [Initial] ---- create_session ----> [Negotiating]
    ///     |                                  |
    ///     |                                  v
    ///     |                         dedicated session with
    ///     |                         SingleConnectPromotion
    ///     |
    ///     +-- server echoes flag --------> [Supported]
    ///     |                                  |
    ///     |                                  v
    ///     |                         use cached shared connection
    ///     |                                  |
    ///     |                                  +-- shared connection is still healthy
    ///     |                                  |       |
    ///     |                                  |       v
    ///     |                                  |   shared session
    ///     |                                  |
    ///     |                                  +-- shared connection disconnects
    ///     |                                          |
    ///     |                                          v
    ///     |                                 clear cache and return to [Initial]
    ///     |                                          |
    ///     |                                          v
    ///     |                                 next create_session renegotiates
    ///     |                                          |
    ///     |                                          +-- new backend echoes flag
    ///     |                                          |       |
    ///     |                                          |       v
    ///     |                                          |   [Supported]
    ///     |                                          |
    ///     |                                          +-- new backend omits flag
    ///     |                                                  |
    ///     |                                                  v
    ///     |                                              [NotSupported]
    ///     |
    ///     +-- server omits flag ---------> [NotSupported]
    ///                                        |
    ///                                        v
    ///                              dedicated sessions only
    /// ```
    ///
    /// After a hard disconnect from a cached shared connection, the next session
    /// probes again because a fresh TCP/TLS connection can connect to a different
    /// TACACS+ server. If that server is behind a load balancer and does not echo
    /// the single-connect flag, negotiation records `NotSupported` and this
    /// client uses dedicated connections for the rest of its lifetime.
    ///
    /// # Why the staged checks?
    ///
    /// This function re-checks state several times because other tasks can
    /// complete probes, lose shared streams, or mark single-connection mode as
    /// unsupported while this task waits. These checks do not repeat TCP
    /// connection attempts:
    ///
    /// 1. If configuration disables single-connection mode, create a fresh
    ///    dedicated connection.
    /// 2. If capability is unknown because preflight was disabled or a cached
    ///    shared connection disconnected, create one dedicated probe. This probe
    ///    determines whether a future shared connection is allowed.
    /// 3. If a probe is already active, use a fresh dedicated connection without a
    ///    promotion so concurrent callers do not race to publish conflicting
    ///    capability results.
    /// 4. If support is known, try the cached shared connection without taking
    ///    a lock. This is the hot path.
    /// 5. If the cached shared connection was rejected, re-read the state
    ///    because the rejection can reset the client to `Initial` or mark it
    ///    `NotSupported`.
    /// 6. Only the recovery path takes `shared_recovery_lock`, preventing many
    ///    concurrent callers from opening replacement probe connections.
    /// 7. After waiting for that lock, try the shared cache again because the
    ///    previous holder can restore it first.
    /// 8. If no shared session is available, perform the one required fallback:
    ///    dedicated-only for `NotSupported`, otherwise a new dedicated probe.
    ///
    /// # Errors
    ///
    /// Returns an error if no shared session can be created and a fresh
    /// dedicated transport cannot be opened.
    pub(super) async fn create_session(&self) -> anyhow::Result<ClientSession> {
        self.create_session_for(None, None).await
    }

    pub(super) async fn create_fixed_session(
        &self,
        expected: ExpectedResponseHeader,
    ) -> anyhow::Result<ClientSession> {
        self.create_session_for(Some(expected), None).await
    }

    pub(super) async fn create_fixed_session_until(
        &self,
        expected: ExpectedResponseHeader,
        deadline: crate::RequestDeadline,
    ) -> anyhow::Result<ClientSession> {
        self.create_session_for(Some(expected), Some(deadline))
            .await
    }

    async fn create_session_for(
        &self,
        expected: Option<ExpectedResponseHeader>,
        deadline: Option<crate::RequestDeadline>,
    ) -> anyhow::Result<ClientSession> {
        self.lifecycle.ensure_open()?;
        let session = self.create_open_session(expected, deadline).await?;
        self.lifecycle.ensure_open()?;
        Ok(session.with_counters(self.endpoint.counters()))
    }

    async fn create_open_session(
        &self,
        expected: Option<ExpectedResponseHeader>,
        deadline: Option<crate::RequestDeadline>,
    ) -> anyhow::Result<ClientSession> {
        if !self.endpoint.single_connection() {
            return Ok(ClientSession::dedicated(
                self.create_fresh_dedicated_session(None, deadline).await?,
            ));
        }

        // Stage 1: unknown capability and active negotiation are decided before
        // looking for a shared cache. Initial occurs only when preflight was
        // disabled or after a cached shared connection disconnected. Only Initial
        // can start the capability probe. Negotiating means another session already
        // owns it.
        match self.single_connection_state() {
            SingleConnectionState::Initial => {
                return self
                    .create_single_connect_negotiation_session(deadline)
                    .await;
            }
            SingleConnectionState::Negotiating | SingleConnectionState::NotSupported => {
                // Negotiating means another session already owns the probe.
                // NotSupported means that the probe denied support. In both
                // cases, open a fresh dedicated connection without promotion.
                return Ok(ClientSession::dedicated(
                    self.create_fresh_dedicated_session(None, deadline).await?,
                ));
            }
            SingleConnectionState::Supported => {}
        }

        // Stage 2: hot path. A confirmed, healthy shared connection can create
        // a session without serializing every caller on the recovery mutex.
        if let Some(session) = self.try_create_shared_session(expected).await {
            return Ok(session);
        }

        self.create_session_after_shared_miss(expected, deadline)
            .await
    }

    /// Opens a sequential packet conversation for transparent proxying and
    /// interactive TACACS+ authentication.
    ///
    /// # Errors
    ///
    /// Returns an error when a dedicated or shared session cannot be created.
    pub async fn open_conversation(&self) -> anyhow::Result<ClientConversation> {
        self.create_session().await.map(ClientConversation::new)
    }

    async fn create_session_after_shared_miss(
        &self,
        expected: Option<ExpectedResponseHeader>,
        deadline: Option<crate::RequestDeadline>,
    ) -> anyhow::Result<ClientSession> {
        // Stage 3: a rejected shared connection returns the client to Initial
        // after transport loss. The next connection must negotiate again.
        match self.single_connection_state() {
            SingleConnectionState::Initial => {
                return self
                    .create_single_connect_negotiation_session(deadline)
                    .await;
            }
            SingleConnectionState::Negotiating | SingleConnectionState::NotSupported => {
                // Active negotiation and terminal denial both use new
                // dedicated connections without promotion.
                return Ok(ClientSession::dedicated(
                    self.create_fresh_dedicated_session(None, deadline).await?,
                ));
            }
            SingleConnectionState::Supported => {}
        }

        // Stage 4: slow-path serialization. Only one task can replace a
        // missing shared connection. Other tasks wait and then check again.
        let _shared_recovery_guard = self.shared_recovery_lock.lock().await;

        // Stage 5: another task can restore the shared cache while this task
        // waits for the recovery lock.
        if let Some(session) = self.try_create_shared_session(expected).await {
            return Ok(session);
        }

        // Stage 6: final fallback. This opens at most one fresh dedicated
        // session on this path. It opens a connection without a probe for
        // NotSupported, or a probe that can promote the completed connection.
        match self.single_connection_state() {
            SingleConnectionState::NotSupported => {
                // Another task can record denial while this task waits
                // on recovery. Keep terminal NotSupported on fresh streams.
                Ok(ClientSession::dedicated(
                    self.create_fresh_dedicated_session(None, deadline).await?,
                ))
            }
            SingleConnectionState::Negotiating => Ok(ClientSession::dedicated(
                self.create_fresh_dedicated_session(None, deadline).await?,
            )),
            SingleConnectionState::Initial | SingleConnectionState::Supported => {
                self.create_single_connect_negotiation_session(deadline)
                    .await
            }
        }
    }

    pub(super) async fn create_single_connect_negotiation_session(
        &self,
        deadline: Option<crate::RequestDeadline>,
    ) -> anyhow::Result<ClientSession> {
        let Some(promotion) = self.begin_single_connection_negotiation() else {
            return Ok(ClientSession::dedicated(
                self.create_fresh_dedicated_session(None, deadline).await?,
            ));
        };

        Ok(ClientSession::dedicated(
            self.create_fresh_dedicated_session(Some(promotion), deadline)
                .await?,
        ))
    }

    pub(super) fn single_connection_state(&self) -> SingleConnectionState {
        self.single_connection_state.snapshot()
    }

    /// Starts or joins single-connection negotiation for a dedicated session.
    ///
    /// The returned promotion object is the response callback for that session:
    /// it records whether the server echoed the single-connect flag and later
    /// receives the completed dedicated connection if promotion is safe.
    ///
    /// ```text
    /// [Initial] ---- begin ----> [Negotiating] -- returns promotion
    /// [Negotiating] -----------> [Negotiating] -- no promotion
    /// [Supported] ---- retry --> [Negotiating] -- returns promotion
    /// [NotSupported] ----------> [NotSupported] -- no promotion
    /// ```
    fn begin_single_connection_negotiation(&self) -> Option<SingleConnectPromotion> {
        SingleConnectPromotion::begin(
            Arc::clone(&self.shared_connection),
            Arc::clone(&self.single_connection_state),
        )
    }

    pub(super) fn update_single_connection_state(&self, new_state: SingleConnectionState) {
        self.single_connection_state.update(new_state);
    }

    /// Updates the client state after the cached shared connection is rejected.
    ///
    /// A cached shared connection can stop accepting sessions for two different
    /// reasons:
    ///
    /// ```text
    /// cached shared connection cannot create a session
    ///     |
    ///     v
    /// inspect cached connection state
    ///     |
    ///     +-- [NotSupported]
    ///     |       |
    ///     |       v
    ///     |   first reply did not confirm single-connect support
    ///     |   mark client [NotSupported]
    ///     |   next session is dedicated without probing
    ///     |
    ///     +-- [Initial] / [Negotiating] / [Supported]
    ///             |
    ///             v
    ///         connection ended without a capability denial
    ///         mark client [Initial]
    ///         next session opens a dedicated probe
    ///             |
    ///             +-- new backend echoes flag --> cache shared connection
    ///             +-- new backend omits flag --> mark [NotSupported]
    /// ```
    ///
    /// The second path is the load-balancer-safe path: after a shared
    /// connection closes, the client does not assume that the next backend has the
    /// same single-connection capability.
    fn update_state_after_shared_connection_rejection(
        &self,
        connection: &Arc<MultiplexedConnection>,
    ) {
        match connection.single_connection_state() {
            SingleConnectionState::NotSupported => {
                self.update_single_connection_state(SingleConnectionState::NotSupported);
            }
            SingleConnectionState::Initial
            | SingleConnectionState::Negotiating
            | SingleConnectionState::Supported => {
                self.update_single_connection_state(SingleConnectionState::Initial);
            }
        }
    }

    async fn try_create_shared_session(
        &self,
        expected: Option<ExpectedResponseHeader>,
    ) -> Option<ClientSession> {
        let connection = self.shared_connection.current().await?;

        if !connection.can_create_sessions() {
            self.clear_shared_connection(&connection).await;
            return None;
        }

        let session = match expected {
            Some(expected) => connection
                .create_fixed_session(expected)
                .map(ClientSession::shared_fixed),
            None => connection.create_session().map(ClientSession::shared),
        };

        match session {
            Ok(session) => Some(session),
            Err(error) => {
                log::debug!(
                    "Cached connection to TACACS+ server {} failed to create a session: {error:#}",
                    self.endpoint.address(),
                );
                self.clear_shared_connection(&connection).await;
                None
            }
        }
    }

    async fn clear_shared_connection(&self, connection: &Arc<MultiplexedConnection>) {
        self.shared_connection
            .clear_if_same(connection, || {
                self.update_state_after_shared_connection_rejection(connection)
            })
            .await;
    }

    /// Creates a dedicated session from a newly opened transport.
    ///
    /// This is the normal dedicated path when configuration disables
    /// clients, concurrent callers while a single-connect probe is active, and
    /// clients whose initial single-connect probe reached terminal `NotSupported`.
    async fn create_fresh_dedicated_session(
        &self,
        single_connect_promotion: Option<SingleConnectPromotion>,
        deadline: Option<crate::RequestDeadline>,
    ) -> anyhow::Result<DedicatedSession> {
        let transport = self
            .lifecycle
            .establish(self.endpoint.clone(), deadline)
            .await?;

        Ok(self.create_dedicated_session_with_transport(transport, single_connect_promotion))
    }

    fn create_dedicated_session_with_transport(
        &self,
        transport: BoxedTransport,
        single_connect_promotion: Option<SingleConnectPromotion>,
    ) -> DedicatedSession {
        let obfuscation_key = self
            .endpoint
            .obfuscation_key
            .as_ref()
            .map(tacacsrs_secrets::SecretBytes::expose_secret);
        DedicatedSession::new(transport, obfuscation_key, single_connect_promotion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stale_shared_rejection_preserves_replacement_and_capability() {
        let client = TacacsClient::from_prepared(crate::PreparedEndpoint::new(
            crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
            crate::PreparedTransport::Tcp,
            true,
            None,
            crate::ConnectOptions::default(),
        ));
        let stale = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
        let replacement = Arc::new(MultiplexedConnection::new_single_connect_confirmed(None, None));
        client
            .shared_connection
            .store_for_test(replacement.clone())
            .await;
        client.update_single_connection_state(SingleConnectionState::Supported);

        for (connection, expected) in [
            (&stale, SingleConnectionState::Supported),
            (&replacement, SingleConnectionState::Initial),
        ] {
            let locked_cache = client.shared_connection.lock_for_test().await;
            let mut rejection = Box::pin(client.clear_shared_connection(connection));
            assert!(futures::poll!(&mut rejection).is_pending());
            assert_eq!(client.single_connection_state(), SingleConnectionState::Supported);
            drop(locked_cache);
            rejection.await;
            assert_eq!(client.single_connection_state(), expected);
            if expected == SingleConnectionState::Supported {
                assert!(Arc::ptr_eq(
                    &client.shared_connection.current().await.unwrap(),
                    &replacement
                ));
                assert!(replacement.can_create_sessions());
            } else {
                assert!(client.shared_connection.current().await.is_none());
            }
        }
    }
}
