//! The standard components of the agent host.
//!
//! An executable selects components from this module, gives each one its
//! settings, and passes them to [`run_until`](crate::host::run_until). The
//! components cover these concerns:
//!
//! - [`DatastoreSourceComponent`]: a configuration datastore and the local
//!   services.
//! - [`ClientApiComponent`]: the local client API over IPC.
//! - [`TacacsProxyComponent`]: the raw TACACS+ proxy.
//! - [`StatisticsComponent`]: a periodic operational statistics file.
//! - [`SystemdComponent`]: readiness and status for systemd.
//! - [`UpstreamWatchdogComponent`]: periodic upstream accounting probes.
//! - [`InvalidSourceShutdownComponent`]: a stop when the configuration
//!   cannot become valid.
//!
//! Provider crates supply other source components, for example SONiC and
//! KubeSONiC.

mod client_api;
mod health_details;
mod source;
mod source_guard;
mod statistics;
mod systemd;
mod tacacs_proxy;
mod watchdog;

pub use client_api::ClientApiComponent;
pub use source::{DatastoreSourceComponent, LocalServicesInput};
pub use source_guard::InvalidSourceShutdownComponent;
pub use statistics::StatisticsComponent;
pub use systemd::{SystemdComponent, SystemdMode};
pub use tacacs_proxy::TacacsProxyComponent;
pub use watchdog::UpstreamWatchdogComponent;
