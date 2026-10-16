//! Deferred dedicated-to-shared promotion during single-connection negotiation.
//!
//! [`SingleConnectPromotion`] is the response callback a dedicated session
//! carries while it probes for single-connection support. It records the first
//! reply synchronously, then defers the connection hand-off until the session
//! completes.
//!
//! # First-reply latch
//!
//! RFC 8907 makes the `TAC_PLUS_SINGLE_CONNECT_FLAG` meaningful only on the
//! first reply of a connection. [`observe_server_response`] latches that first
//! reply with an atomic compare-and-exchange from the pending state, so later
//! replies on the same dedicated session cannot change the outcome.
//!
//! ```text
//! send request with single-connect flag
//!     |
//!     v
//! [Pending] --- first reply has flag ----> [Supported] (later replies ignored)
//!     |
//!     +--------- first reply lacks flag --> [Unsupported] (later replies ignored)
//! ```
//!
//! # Deferred promotion and the cache fence
//!
//! The dedicated session owns the reader and writer halves until it completes,
//! so promotion is deferred to [`promote_if_confirmed`]. A confirmed connection
//! is handed to [`SharedConnectionCache::publish_if_current`] with the epoch
//! captured at construction. The cache upgrades and stores it only while the
//! epoch still matches and the client has not closed, so a retirement or close
//! that happened during the probe wins over the late promotion.
//!
//! [`observe_server_response`]: SingleConnectPromotion::observe_server_response
//! [`promote_if_confirmed`]: SingleConnectPromotion::promote_if_confirmed

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use tokio::sync::RwLock;

use tacacsrs_protocol::enumerations::TacacsFlags;
use tacacsrs_protocol::packet::{Packet, PacketTrait};

use crate::connection::BoxedDedicatedConnection;
use crate::single_connect::SingleConnectionState;
use crate::single_connect::cache::SharedConnectionCache;

const SINGLE_CONNECT_RESPONSE_PENDING: u8 = 0;
const SINGLE_CONNECT_RESPONSE_UNSUPPORTED: u8 = 1;
const SINGLE_CONNECT_RESPONSE_SUPPORTED: u8 = 2;

/// Deferred promotion from a dedicated connection to a cached shared connection.
///
/// This is the callback carried by a dedicated session during TACACS+
/// single-connection negotiation. It records the server response synchronously
/// when a packet arrives. It does not convert the connection at that point. The
/// dedicated session owns the reader and writer halves until completion.
pub(crate) struct SingleConnectPromotion {
    shared_connection: Arc<SharedConnectionCache>,
    cache_generation: u64,
    state: Arc<RwLock<SingleConnectionState>>,
    response: AtomicU8,
}

impl SingleConnectPromotion {
    /// Captures the cache epoch so a later promotion can detect a retirement.
    pub(crate) fn new(
        shared_connection: Arc<SharedConnectionCache>,
        state: Arc<RwLock<SingleConnectionState>>,
    ) -> Self {
        Self {
            cache_generation: shared_connection.generation(),
            shared_connection,
            state,
            response: AtomicU8::new(SINGLE_CONNECT_RESPONSE_PENDING),
        }
    }

    /// Latches the first reply's single-connect flag and ignores later replies.
    ///
    /// The compare-and-exchange only succeeds from the pending state, so the
    /// first reply alone decides single-connection support.
    pub(crate) fn observe_server_response(&self, packet: &Packet) {
        let response = if packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
        {
            SINGLE_CONNECT_RESPONSE_SUPPORTED
        } else {
            SINGLE_CONNECT_RESPONSE_UNSUPPORTED
        };

        let _ = self.response.compare_exchange(
            SINGLE_CONNECT_RESPONSE_PENDING,
            response,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Promotes the completed connection to the shared cache when confirmed.
    ///
    /// The upgrade is deferred to the cache fence so a close or newer epoch that
    /// occurred during the probe cannot be overwritten. Unsupported and
    /// never-answered probes shut the dedicated connection down instead.
    pub(crate) async fn promote_if_confirmed(&self, mut connection: BoxedDedicatedConnection) {
        match self.response.load(Ordering::Acquire) {
            SINGLE_CONNECT_RESPONSE_SUPPORTED => {
                if self.record_server_result(true).await {
                    self.shared_connection
                        .publish_if_current(self.cache_generation, move || connection.upgrade())
                        .await;
                }
            }
            SINGLE_CONNECT_RESPONSE_UNSUPPORTED => {
                self.record_server_result(false).await;
                connection.shutdown().await;
            }
            SINGLE_CONNECT_RESPONSE_PENDING => {
                connection.shutdown().await;
            }
            _ => unreachable!("invalid single-connect response state"),
        }
    }

    /// Records the negotiated capability, refusing to upgrade a terminal denial.
    ///
    /// Returns whether the caller may publish the connection. A `NotSupported`
    /// state is terminal for the client, so a late support confirmation from a
    /// different backend is ignored.
    async fn record_server_result(&self, supported: bool) -> bool {
        let mut state = self.state.write().await;
        let new_state = if supported {
            SingleConnectionState::Supported
        } else {
            SingleConnectionState::NotSupported
        };

        if *state == SingleConnectionState::NotSupported
            && new_state == SingleConnectionState::Supported
        {
            log::debug!(
                target: "tacacsrs_networking::single_connect",
                "Ignored late single-connect support confirmation because the state is NotSupported",
            );
            return false;
        }

        if *state != new_state {
            log::info!(
                target: "tacacsrs_networking::single_connect",
                "Single-connection state changed from {:?} to {:?}",
                *state,
                new_state,
            );
            *state = new_state;
        }

        supported
    }
}
