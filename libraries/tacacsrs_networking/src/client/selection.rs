//! Session selection and the TACACS+ single-connection state machine.
//!
//! These [`TacacsClient`] methods choose a dedicated or shared session for each
//! operation and drive the single-connection capability state. The client holds
//! the shared-connection cache as a capability; the
//! [`single_connect`](crate::single_connect) module owns the cache slot, epoch,
//! closed flag, and the publication fence.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::Notify;

use crate::connection::MultiplexedConnection;
use crate::session::{ClientConversation, ClientSession, DedicatedSession, ExpectedResponseHeader};
use crate::single_connect::{FirstReplyPublication, SingleConnectionState};
use crate::transport::{BoxedTransport, Transport};

use super::TacacsClient;

#[derive(Clone)]
enum ConnectAttemptState {
    Pending,
    Ready,
    Retry,
    Failed(String),
}

pub(super) struct ConnectAttempt {
    state: Mutex<ConnectAttemptState>,
    notify: Notify,
}

impl ConnectAttempt {
    fn new() -> Self {
        Self {
            state: Mutex::new(ConnectAttemptState::Pending),
            notify: Notify::new(),
        }
    }

    pub(super) fn wake_waiters(&self) {
        self.notify.notify_waiters();
    }

    fn finish(&self, next: ConnectAttemptState) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*state, ConnectAttemptState::Pending) {
            *state = next;
            drop(state);
            self.notify.notify_waiters();
        }
    }

    async fn wait(
        &self,
        is_open: impl Fn() -> anyhow::Result<()>,
        deadline: Option<crate::RequestDeadline>,
    ) -> anyhow::Result<()> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            is_open()?;
            match self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
            {
                ConnectAttemptState::Pending => {}
                ConnectAttemptState::Ready | ConnectAttemptState::Retry => return Ok(()),
                ConnectAttemptState::Failed(message) => return Err(anyhow::Error::msg(message)),
            }
            match deadline {
                Some(deadline) => deadline.run(notified).await?,
                None => notified.await,
            }
        }
    }
}

struct ConnectAttemptGuard<'client> {
    slot: &'client Mutex<Option<Arc<ConnectAttempt>>>,
    attempt: Option<Arc<ConnectAttempt>>,
}

impl<'client> ConnectAttemptGuard<'client> {
    fn clear_slot_and_finish(&mut self, next: ConnectAttemptState) {
        let Some(attempt) = self.attempt.take() else {
            return;
        };
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &attempt))
        {
            *slot = None;
        }
        drop(slot);
        attempt.finish(next);
    }

    fn complete_ready(mut self) {
        self.clear_slot_and_finish(ConnectAttemptState::Ready);
    }

    fn fail_for_waiters(mut self, message: String) {
        self.clear_slot_and_finish(ConnectAttemptState::Failed(message));
    }
}

impl Drop for ConnectAttemptGuard<'_> {
    fn drop(&mut self) {
        self.clear_slot_and_finish(ConnectAttemptState::Retry);
    }
}

impl TacacsClient {
    /// Creates a client session suitable for running TACACS+ flows.
    ///
    /// When `single_connection` is enabled, the first session opens a
    /// negotiating [`MultiplexedConnection`] and sends `TAC_PLUS_SINGLE_CONNECT_FLAG`
    /// on its first packet. Concurrent callers wait for the first reply on that
    /// connection:
    ///
    /// - If the first reply echoes `TAC_PLUS_SINGLE_CONNECT_FLAG`, the
    ///   connection is published into [`SharedConnectionCache`](crate::single_connect::SharedConnectionCache)
    ///   immediately on that first reply and waiting callers multiplex onto the
    ///   same connection without opening extra transports.
    /// - If the first reply omits `TAC_PLUS_SINGLE_CONNECT_FLAG`, the client
    ///   records terminal `NotSupported` and wakes waiting callers to open
    ///   dedicated connections while the initial session finishes and closes its
    ///   connection on completion.
    /// - If the initial probe fails or is cancelled before a valid first reply
    ///   arrives, negotiation resets to `Initial` and the next caller probes.
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
                self.create_fresh_dedicated_session(deadline).await?,
            ));
        }

        loop {
            self.lifecycle.ensure_open()?;
            if let Some(deadline) = deadline {
                deadline.check()?;
            }

            match self.single_connection_state() {
                SingleConnectionState::NotSupported => {
                    return Ok(ClientSession::dedicated(
                        self.create_fresh_dedicated_session(deadline).await?,
                    ));
                }
                SingleConnectionState::Supported => {
                    if let Some(session) = self.try_create_shared_session(expected).await {
                        return Ok(session);
                    }
                }
                SingleConnectionState::Negotiating => {
                    self.single_connection_state
                        .wait_while_negotiating(|| self.lifecycle.ensure_open(), deadline)
                        .await?;
                    continue;
                }
                SingleConnectionState::Initial => {}
            }

            let existing_attempt = {
                let mut pending = self
                    .pending_connect
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if let Some(attempt) = pending.as_ref().cloned() {
                    Some(attempt)
                } else {
                    match self.single_connection_state() {
                        SingleConnectionState::NotSupported
                        | SingleConnectionState::Negotiating => {
                            drop(pending);
                            continue;
                        }
                        SingleConnectionState::Initial | SingleConnectionState::Supported => {
                            let attempt = Arc::new(ConnectAttempt::new());
                            *pending = Some(Arc::clone(&attempt));
                            None
                        }
                    }
                }
            };

            if let Some(attempt) = existing_attempt {
                attempt
                    .wait(|| self.lifecycle.ensure_open(), deadline)
                    .await?;
                continue;
            }

            let attempt = self
                .pending_connect
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .cloned();
            let Some(attempt) = attempt else {
                continue;
            };
            let guard = ConnectAttemptGuard {
                slot: &self.pending_connect,
                attempt: Some(attempt),
            };

            self.lifecycle.ensure_open()?;
            if let Some(deadline) = deadline {
                deadline.check()?;
            }

            if self.single_connection_state() == SingleConnectionState::Supported {
                if let Some(session) = self.try_create_shared_session(expected).await {
                    guard.complete_ready();
                    return Ok(session);
                }
            }

            let transport = match self
                .lifecycle
                .establish(self.endpoint.clone(), deadline)
                .await
            {
                Ok(transport) => transport,
                Err(error) => {
                    let caller_cancelled = deadline.is_some_and(|d| d.check().is_err())
                        || self.lifecycle.ensure_open().is_err();
                    if !caller_cancelled {
                        guard.fail_for_waiters(format!("{error:#}"));
                    }
                    return Err(error);
                }
            };

            let session = self.start_negotiating_session_with_transport(transport, expected)?;
            guard.complete_ready();
            return Ok(session);
        }
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

    #[cfg(test)]
    pub(super) async fn create_single_connect_negotiation_session(
        &self,
        expected: Option<ExpectedResponseHeader>,
        deadline: Option<crate::RequestDeadline>,
    ) -> anyhow::Result<ClientSession> {
        let transport = self
            .lifecycle
            .establish(self.endpoint.clone(), deadline)
            .await?;
        self.start_negotiating_session_with_transport(transport, expected)
    }

    fn start_negotiating_session_with_transport(
        &self,
        transport: BoxedTransport,
        expected: Option<ExpectedResponseHeader>,
    ) -> anyhow::Result<ClientSession> {
        let Some(publication) = self.begin_single_connection_negotiation() else {
            return Ok(ClientSession::dedicated(
                self.create_dedicated_session_with_transport(transport),
            ));
        };

        let counters = transport.counters();
        let connection = Arc::new(MultiplexedConnection::new_negotiating(
            self.endpoint.obfuscation_key.clone(),
            self.endpoint.packet_body_limit(),
            counters,
            publication,
            Arc::downgrade(&self.shared_connection),
            Arc::downgrade(&self.single_connection_state),
        ));
        let session = match expected {
            Some(expected) => connection
                .create_fixed_session(expected)
                .map(ClientSession::shared_fixed)?,
            None => connection.create_session().map(ClientSession::shared)?,
        };
        let (reader, writer) = transport.split();
        connection.run_with_halves(reader, writer);
        Ok(session)
    }

    pub(super) fn single_connection_state(&self) -> SingleConnectionState {
        self.single_connection_state.snapshot()
    }

    fn begin_single_connection_negotiation(&self) -> Option<FirstReplyPublication> {
        FirstReplyPublication::begin(
            Arc::clone(&self.shared_connection),
            Arc::clone(&self.single_connection_state),
        )
    }

    pub(super) fn update_single_connection_state(&self, new_state: SingleConnectionState) {
        self.single_connection_state.update(new_state);
    }

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

    async fn create_fresh_dedicated_session(
        &self,
        deadline: Option<crate::RequestDeadline>,
    ) -> anyhow::Result<DedicatedSession> {
        let transport = self
            .lifecycle
            .establish(self.endpoint.clone(), deadline)
            .await?;

        Ok(self.create_dedicated_session_with_transport(transport))
    }

    fn create_dedicated_session_with_transport(
        &self,
        transport: BoxedTransport,
    ) -> DedicatedSession {
        let obfuscation_key = self
            .endpoint
            .obfuscation_key
            .as_ref()
            .map(tacacsrs_secrets::SecretBytes::expose_secret);
        DedicatedSession::new_with_limit(
            transport,
            obfuscation_key,
            self.endpoint.packet_body_limit(),
        )
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
