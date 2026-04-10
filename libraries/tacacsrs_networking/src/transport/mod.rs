//! Transport implementations and shared abstractions.
//!
//! This module organizes transport support into dedicated submodules:
//! - [`abstractions`] for common transport traits and shared logic
//! - [`tcp`] for plain TCP transport support
//! - [`tls`] for TLS transport support
//! - [`tls_psk`] for TLS-PSK transport support (feature-gated)

pub mod abstractions;
pub mod boxed;
pub mod mock;
pub mod tcp;
pub mod tls;
#[cfg(feature = "psk")]
pub mod tls_psk;
#[cfg(feature = "rpk")]
pub mod tls_rpk;

pub use abstractions::Transport;
pub use boxed::BoxedTransport;
