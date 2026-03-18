//! Local listener, failover coordinator, and graceful-shutdown behavior.
//!
//! The crate-level documentation includes the module hierarchy, request
//! activity diagram, and failover state chart for this service implementation.

mod config;
mod coordinator;
mod state;

pub use config::ServiceConfig;
pub use coordinator::TacacsClientService;

#[cfg(test)]
mod tests;
