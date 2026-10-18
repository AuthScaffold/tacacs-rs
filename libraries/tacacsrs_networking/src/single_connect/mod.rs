//! TACACS+ single-connection capability negotiation and shared-connection ownership.
//!
//! This module owns the full lifecycle of TACACS+ single-connection mode:
//! capability state, the deferred dedicated-to-shared promotion, and the private
//! cache that holds a promoted connection. Keeping promotion and the cache
//! together means the client and the dedicated session hold capabilities, not
//! raw cache fields, and no other scope can publish a connection outside the
//! guarded fence.
//!
//! # State flow
//!
//! ```text
//!            first create_session
//! [Initial] ----------------------> [Negotiating] -- dedicated probe carries a promotion
//!    ^                                   |
//!    |                                   | first reply latched (compare-and-exchange)
//!    |                                   v
//!    |            flag set? --+-- yes --> [Supported] ---> promote + cache under the fence
//!    |                        |
//!    |                        +-- no  --> [NotSupported] (terminal) ---> dedicated only
//!    |
//!    +-- cached shared connection lost, no capability denial -- reset and reprobe
//! ```
//!
//! - **First-reply latch** ([`promotion`]): the first reply alone decides
//!   support. [`SingleConnectPromotion::observe_server_response`] uses an atomic
//!   compare-and-exchange from the pending state, so later replies are ignored.
//! - **Deferred promotion** ([`promotion`]): the dedicated session keeps its
//!   transport halves until completion, then hands a confirmed connection to the
//!   cache fence.
//! - **Cache fence** ([`cache`]): [`SharedConnectionCache::publish_if_current`]
//!   checks the closed flag and the epoch counter while the slot write lock is
//!   held and before the connection is upgraded, so a concurrent close or
//!   retirement is never overwritten.
//! - **Cancel and shutdown** ([`cache`]): the client marks the cache closed and
//!   advances the epoch, moving the cached connection into retirement. Promotions
//!   captured before that epoch cannot repopulate the slot.
//! - **Epoch counters**: the cache generation fences retirement. The negotiation
//!   epoch fences abandoned probes and stale results. Promotion checks both under
//!   the cache lock.
//!
//! [`SingleConnectPromotion::observe_server_response`]: promotion::SingleConnectPromotion::observe_server_response
//! [`SharedConnectionCache::publish_if_current`]: cache::SharedConnectionCache::publish_if_current

mod cache;
mod promotion;
mod state;
mod tracker;

pub(crate) use cache::SharedConnectionCache;
pub(crate) use promotion::SingleConnectPromotion;
pub(crate) use state::{NegotiationState, SingleConnectionState};
pub(crate) use tracker::{LocalSingleConnectState, SingleConnectFlag};
