//! First-reply publication for single-connection negotiation.
//!
//! [`FirstReplyPublication`] settles a negotiating [`MultiplexedConnection`] as
//! soon as its first validated server reply arrives.
//!
//! - When `TAC_PLUS_SINGLE_CONNECT_FLAG` is set, the connection is published
//!   immediately into [`SharedConnectionCache`] under the captured generation
//!   fence and all gated callers wake to multiplex onto it, even while the
//!   initial session continues a multi-round authentication conversation.
//! - When `TAC_PLUS_SINGLE_CONNECT_FLAG` is absent, [`NegotiationState`] moves
//!   to terminal [`SingleConnectionState::NotSupported`] and gated callers wake
//!   immediately to open dedicated connections while the initial session finishes
//!   and closes its connection on completion.
//! - If the connection or initial session ends before a valid first reply
//!   arrives, dropping [`FirstReplyPublication`] resets [`NegotiationState`] to
//!   [`SingleConnectionState::Initial`] and wakes the next waiter to probe.
//!
//! [`SingleConnectionState::Initial`]: crate::single_connect::SingleConnectionState::Initial
//! [`SingleConnectionState::NotSupported`]: crate::single_connect::SingleConnectionState::NotSupported

use std::sync::Arc;

use crate::connection::MultiplexedConnection;
use crate::single_connect::cache::SharedConnectionCache;
use crate::single_connect::{NegotiationState, SingleConnectFlag};

/// One-shot capability publication owned by a negotiating [`MultiplexedConnection`].
pub(crate) struct FirstReplyPublication {
    shared_connection: Arc<SharedConnectionCache>,
    cache_generation: u64,
    state: Arc<NegotiationState>,
    epoch: u64,
}

impl std::fmt::Debug for FirstReplyPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirstReplyPublication")
            .field("cache_generation", &self.cache_generation)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl FirstReplyPublication {
    /// Captures the cache epoch so a later retirement or close blocks publication.
    pub(crate) fn begin(
        shared_connection: Arc<SharedConnectionCache>,
        state: Arc<NegotiationState>,
    ) -> Option<Self> {
        let epoch = state.begin()?;
        Some(Self {
            cache_generation: shared_connection.generation(),
            shared_connection,
            state,
            epoch,
        })
    }

    /// Settles capability from the first validated reply on `connection`.
    pub(crate) async fn settle(
        self,
        connection: &Arc<MultiplexedConnection>,
        flag: SingleConnectFlag,
        counters: Option<&crate::ServerCounters>,
    ) {
        let supported = flag == SingleConnectFlag::Set;
        if let Some(counters) = counters {
            counters.single_connect(supported);
        }

        if supported {
            let candidate = Arc::clone(connection);
            let mut published = false;
            self.shared_connection
                .publish_if_current(self.cache_generation, || {
                    let mut stored = None;
                    self.state.settle(self.epoch, true, || {
                        published = true;
                        stored = Some(candidate);
                    });
                    stored
                })
                .await;
            if !published {
                connection.disable_new_sessions();
                self.state.abandon(self.epoch);
            }
        } else {
            let mut settled = false;
            self.shared_connection
                .publish_if_current(self.cache_generation, || {
                    self.state.settle(self.epoch, false, || {
                        settled = true;
                    });
                    None
                })
                .await;
            if !settled {
                self.state.abandon(self.epoch);
            }
        }
    }
}

impl Drop for FirstReplyPublication {
    fn drop(&mut self) {
        self.state.abandon(self.epoch);
    }
}
