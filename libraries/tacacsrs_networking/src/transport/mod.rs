//! Transport implementations and shared abstractions.
//!
//! This module organizes transport support into dedicated submodules:
//! - [`abstractions`] for common transport traits and shared logic
//! - [`tcp`] for plain TCP transport support
//! - `tls` for TLS transport support (crate-internal; constructed via
//!   [`crate::establish::establish_stream`])
//! - `tls_psk` for TLS-PSK transport support (feature-gated, crate-internal;
//!   constructed via [`crate::establish::establish_stream`])

pub(crate) mod abstractions;
pub(crate) mod boxed;
#[cfg(test)]
pub(crate) mod mock;
pub(crate) mod tcp;
pub(crate) mod tls;
#[cfg(feature = "psk")]
pub(crate) mod tls_psk;

pub(crate) use abstractions::Transport;
pub(crate) use boxed::BoxedTransport;
