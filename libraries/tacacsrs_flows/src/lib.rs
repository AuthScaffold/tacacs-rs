//! TACACS+ client flow implementations.
//!
//! This crate hosts protocol "flow logic" that runs on top of session I/O.
//! Session management (channel ownership, sequence/state lifecycle, connection behavior)
//! stays in `tacacsrs-networking`; flows here depend only on
//! `tacacsrs-flow-abstractions` traits so they can be reused and replaced by
//! custom flow crates without requiring networking to depend on a concrete flow crate.
//!
//! The accounting flow is the first extracted flow. Future multi-turn flows
//! (e.g. interactive Authentication/Authorization exchanges) should follow the same pattern:
//! define minimal I/O traits and keep protocol state-machine logic in this crate.

pub mod accounting;
