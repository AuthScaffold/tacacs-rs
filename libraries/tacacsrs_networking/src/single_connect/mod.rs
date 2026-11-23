//! TACACS+ single-connection capability negotiation and shared-connection ownership.
//!
//! This module owns the full lifecycle of TACACS+ single-connection mode:
//! capability state, first-reply publication from a negotiating multiplexed
//! connection, and the private cache that holds the confirmed shared connection.
//!
//! # State flow
//!
//! ```text
//!            first create_session
//! [Initial] ----------------------> [Negotiating] -- concurrent callers wait on Notify
//!    ^                                   |
//!    |                                   | first validated reply arrives
//!    |                                   v
//!    |            flag set? --+-- yes --> [Supported] ---> publish under cache fence + wake waiters
//!    |                        |
//!    |                        +-- no  --> [NotSupported] (terminal) ---> wake waiters for dedicated mode
//!    |
//!    +-- cached shared connection lost, no capability denial -- reset and reprobe
//! ```
//!
//! - **First-reply gate** ([`state`]): concurrent callers wait while a probe is
//!   in [`SingleConnectionState::Negotiating`] until the first reply settles
//!   capability or the probe abandons.
//! - **First-reply publication** ([`promotion`]): [`FirstReplyPublication::settle`]
//!   publishes the negotiating [`MultiplexedConnection`](crate::connection::MultiplexedConnection)
//!   into the cache immediately on the first validated reply, even when the
//!   negotiating session continues a multi-round authentication conversation.
//! - **Cache fence** ([`cache`]): [`SharedConnectionCache::publish_if_current`]
//!   checks the closed flag and the epoch counter while the slot write lock is
//!   held, so a concurrent close or retirement is never overwritten.
//!
//! [`FirstReplyPublication::settle`]: promotion::FirstReplyPublication::settle
//! [`SharedConnectionCache::publish_if_current`]: cache::SharedConnectionCache::publish_if_current

mod cache;
mod promotion;
mod state;
mod tracker;

pub(crate) use cache::SharedConnectionCache;
pub(crate) use promotion::FirstReplyPublication;
pub(crate) use state::{NegotiationState, SingleConnectionState};
pub(crate) use tracker::{LocalSingleConnectState, SingleConnectFlag};
