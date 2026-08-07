//! Typed TACACS+ operation descriptors.
//!
//! Fixed exchanges serialize operation-specific request bodies and parse typed
//! replies. Networking owns transport selection, packet headers, sequencing,
//! multiplexing, timeout, and lifecycle behavior.

pub mod accounting;
pub mod authentication;
pub mod authorization;
