//! TACACS+ protocol flow implementations.
//!
//! This crate provides reusable, transport-agnostic implementations of TACACS+
//! client-side protocol flows. It is designed to be independent of any specific
//! session or networking implementation.
//!
//! # Architecture
//!
//! Flows operate through the [`ClientSessionIo`] trait, which abstracts the
//! minimal session I/O needed by protocol flows: sequence numbers, session IDs,
//! packet send/receive, and completion signaling. Any session type that
//! implements this trait can be used with the flows in this crate.
//!
//! # Available Flows
//!
//! - **[`accounting`]**: Client-side Accounting request/reply flow.
//!
//! # Adding Future Flows (AuthN / AuthZ)
//!
//! Future authentication and authorization flows should follow the same pattern:
//!
//! 1. Create a new module (e.g., `authentication.rs`, `authorization.rs`).
//! 2. Implement the flow as an async function or struct that accepts
//!    `&dyn ClientSessionIo` (or a generic `T: ClientSessionIo`).
//! 3. For multi-turn flows (e.g., ASCII interactive login, CHAP), consider a
//!    state-machine struct that holds intermediate state and exposes
//!    `async fn next_step(&mut self, ...) -> FlowState` style methods,
//!    allowing callers to drive each turn.
//!
//! The [`ClientSessionIo`] trait is intentionally minimal so flows remain
//! decoupled from connection management, transport, and session lifecycle
//! details that belong in `tacacsrs-networking`.

pub mod accounting;

mod session_io;
pub use session_io::ClientSessionIo;
