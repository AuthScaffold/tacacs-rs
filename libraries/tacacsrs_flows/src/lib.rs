//! Typed TACACS+ operation descriptors.
//!
//! Fixed exchanges serialize operation-specific request bodies and parse typed
//! replies. The networking crate selects the transport and creates packet
//! headers. It also manages sequencing, multiplexing, timeouts, and lifecycles.

pub mod accounting;
pub mod authentication;
pub mod authorization;
