//! TLS connection implementation for TACACS+ protocol.
//!
//! This module provides backwards compatibility re-exports from the unified
//! [`connection`](crate::connection) module.
//!
//! # Migration Guide
//!
//! The `TlsConnection` type is now a type alias for [`Connection`](crate::connection::Connection).
//! Existing code should continue to work, but consider migrating to use `Connection` directly:
//!
//! ```no_run
//! // Old way (still works)
//! use tacacsrs_networking::tls_connection::{TlsConnection, TLSConnectionTrait};
//!
//! // New way (recommended)
//! use tacacsrs_networking::connection::Connection;
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::connection::Connection;
use crate::traits::SessionManagementTrait;

/// Trait for TLS connection operations.
///
/// This trait is preserved for backwards compatibility. New code should use
/// [`Connection`] directly with the [`Transport`](crate::transport::Transport) trait.
#[async_trait]
pub trait TLSConnectionTrait: SessionManagementTrait {
    /// Starts the connection handler for the given TLS stream.
    async fn run(self: &Arc<Self>, stream: TlsStream<TcpStream>) -> anyhow::Result<()>;
}

/// TLS connection handler for TACACS+ protocol.
///
/// This is a type alias for [`Connection`] maintained for backwards compatibility.
pub type TlsConnection = Connection;

impl TlsConnection {
    /// Creates a new TLS connection with an optional obfuscation key.
    ///
    /// Note: For new code, prefer using `Connection::new()` directly.
    #[deprecated(since = "0.2.0", note = "Use Connection::new() instead")]
    pub fn new_tls(obfuscation_key: Option<&[u8]>) -> Self {
        Connection::new(obfuscation_key)
    }
}

#[async_trait]
impl TLSConnectionTrait for TlsConnection {
    async fn run(self: &Arc<Self>, stream: TlsStream<TcpStream>) -> anyhow::Result<()> {
        Connection::run(self, stream).await
    }
}

// Re-export the SessionManagementTrait implementation from Connection
// (it's already implemented on Connection, which TlsConnection aliases to)
