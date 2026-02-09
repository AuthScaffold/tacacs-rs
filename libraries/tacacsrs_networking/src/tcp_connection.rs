//! TCP connection implementation for TACACS+ protocol.
//!
//! This module provides backwards compatibility re-exports from the unified
//! [`connection`](crate::connection) module.
//!
//! # Migration Guide
//!
//! The `TcpConnection` type is now a type alias for [`Connection`](crate::connection::Connection).
//! Existing code should continue to work, but consider migrating to use `Connection` directly:
//!
//! ```no_run
//! // Old way (still works)
//! use tacacsrs_networking::tcp_connection::{TcpConnection, TcpConnectionTrait};
//!
//! // New way (recommended)
//! use tacacsrs_networking::connection::Connection;
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::connection::Connection;
use crate::traits::SessionManagementTrait;

/// Trait for TCP connection operations.
///
/// This trait is preserved for backwards compatibility. New code should use
/// [`Connection`] directly with the [`Transport`](crate::transport::Transport) trait.
#[async_trait]
pub trait TcpConnectionTrait: SessionManagementTrait {
    /// Creates a new TCP connection with an optional obfuscation key.
    fn new(obfuscation_key: Option<&[u8]>) -> Self;

    /// Starts the connection handler for the given TCP stream.
    async fn run(self: &Arc<Self>, stream: TcpStream) -> anyhow::Result<()>;
}

/// TCP connection handler for TACACS+ protocol.
///
/// This is a type alias for [`Connection`] maintained for backwards compatibility.
pub type TcpConnection = Connection;

#[async_trait]
impl TcpConnectionTrait for TcpConnection {
    fn new(obfuscation_key: Option<&[u8]>) -> Self {
        Connection::new(obfuscation_key)
    }

    async fn run(self: &Arc<Self>, stream: TcpStream) -> anyhow::Result<()> {
        Connection::run(self, stream).await
    }
}

// Re-export the SessionManagementTrait implementation from Connection
// (it's already implemented on Connection, which TcpConnection aliases to)
