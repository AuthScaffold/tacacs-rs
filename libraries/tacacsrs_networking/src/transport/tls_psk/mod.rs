//! TLS 1.3 Pre-Shared Key (PSK) transport for TACACS+ connections.
//!
//! Connections are constructed exclusively through
//! [`establish_from_server`], which interprets a [`TacacsPlusServer`]
//! configuration (specifically, the `client-identity.tls13-epsk` container)
//! and performs the TLS-PSK handshake. Internal helpers are not part of the
//! public API; callers should drive the dispatcher in [`crate::establish`]
//! instead.
//!
//! [`TacacsPlusServer`]: tacacsrs_config::TacacsPlusServer

mod config;
mod context;
mod ffi;
mod from_server;
mod tls13_epsk;

pub(crate) use config::PskClientConfig;
pub(crate) use context::{EpskSupportedHashExt, PskDheKeGroups};
pub(crate) use from_server::{establish_from_server, server_has_psk};
