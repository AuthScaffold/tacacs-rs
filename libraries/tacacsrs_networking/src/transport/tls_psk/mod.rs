//! TLS 1.3 pre-shared key (PSK) transport for TACACS+ connections.
//!
//! [`prepare_from_server`] prepares the `client-identity.tls13-epsk`
//! configuration before connection establishment. The context supports repeated
//! handshakes. Callers use the dispatcher in [`crate::establish`].
//!
//! [`TacacsPlusServer`]: tacacsrs_config::TacacsPlusServer

mod config;
mod context;
mod ffi;
mod from_server;
mod tls13_epsk;

pub(crate) use config::PskClientConfig;
pub(crate) use context::PskDheKeGroups;
pub(crate) use from_server::{prepare_from_server, server_has_psk};
