//! Shared test PKI, TLS/PSK server callbacks, and scripted TACACS+ upstream peers.
//!
//! This crate exists only for integration and scenario testing. Architecture
//! validation forbids production crates in `default-members` from depending on it.

pub mod pki;
pub mod psk_peer;
pub mod upstream;
