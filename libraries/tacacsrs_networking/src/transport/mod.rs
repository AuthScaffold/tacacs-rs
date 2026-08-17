//! Transport implementations and shared abstractions.
//!
//! This module contains:
//! - [`abstractions`] for common transport traits and shared logic,
//! - [`tcp`] for TCP transport,
//! - `tls` for crate-internal TLS transport, and
//! - `tls_psk` for crate-internal TLS-PSK transport.
//!
//! [`crate::establish::establish_stream`] constructs TLS transports.

pub(crate) mod abstractions;
pub(crate) mod boxed;
#[cfg(test)]
pub(crate) mod mock;
pub(crate) mod tcp;
pub(crate) mod tls;
pub(crate) mod tls_psk;

pub(crate) use abstractions::Transport;
pub(crate) use boxed::BoxedTransport;
