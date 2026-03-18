//! Local listener, failover coordinator, and graceful-shutdown behavior.
//!
//! This module is the heart of the central TACACS+ client service runtime.
//! It contains the public entry point ([`TacacsClientService`]), the
//! configuration consumed at startup ([`ServiceConfig`]), the internal
//! failover state machine, and integration tests.
//!
//! # Submodule responsibilities
//!
//! | Submodule | Role |
//! |-----------|------|
//! | `config` | Public listener and failover configuration |
//! | `coordinator` | Long-lived service runtime and IPC listener lifecycle |
//! | `state` | Internal failover state, request routing, and active-client tracking |
//! | `tests` | Integration tests covering failover, warm-up, and socket lifecycle |

mod config;
mod coordinator;
mod state;

pub use config::ServiceConfig;
pub use coordinator::TacacsClientService;

#[cfg(test)]
mod tests;
