//! TLS 1.3 pre-shared key (PSK) transport for TACACS+ connections.
//!
//! Context preparation uses an explicit identity, protected key, hash, and
//! ordered key-exchange groups. Callers use prepared endpoints for execution.

mod config;
mod context;
mod ffi;

pub use config::PskClientConfig;
pub(crate) use context::PskDheKeGroups;
pub use context::{PskHash, PskDheGroup};
