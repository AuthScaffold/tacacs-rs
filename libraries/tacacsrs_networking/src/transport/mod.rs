//! Transport implementations and shared abstractions.
//!
//! This module organizes transport support into dedicated submodules:
//! - [`abstractions`] for common transport traits and shared logic
//! - [`tcp`] for plain TCP transport support
//! - `tls` for TLS transport support (crate-internal; constructed via
//!   [`crate::config_connect::establish_stream`])
//! - `tls_psk` for TLS-PSK transport support (feature-gated, crate-internal;
//!   constructed via [`crate::config_connect::establish_stream`])

pub mod abstractions;
pub mod boxed;
pub mod mock;
pub mod tcp;
pub(crate) mod tls;
#[cfg(feature = "psk")]
pub(crate) mod tls_psk;

pub use abstractions::Transport;
pub use boxed::BoxedTransport;
