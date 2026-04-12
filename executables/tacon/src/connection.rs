use std::sync::Arc;

use anyhow::Context;
use tacacsrs_credentials::ResolvedServer;
use tacacsrs_networking::{
    BoxedTransport,
    config_connect::{self, ConnectOptions},
    connection::TacacsConnection,
    session::Session,
    traits::SessionManagementTrait,
};

/// Represents an active TACACS+ connection (either plain TCP or TLS)
pub struct Connection {
    inner: Arc<TacacsConnection>,
}

impl Connection {
    /// Creates a new session on this connection
    ///
    /// # Errors
    ///
    /// Returns an error if session creation fails on the underlying connection.
    pub async fn create_session(&self) -> anyhow::Result<Session> {
        self.inner.create_session().await
    }

    /// Creates a session with a specific session ID on this connection
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID is already in use or if session creation fails.
    pub async fn create_session_with_id(&self, session_id: u32) -> anyhow::Result<Session> {
        self.inner.create_session_with_id(session_id).await
    }

    /// Creates a session, optionally with a specific session ID
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID is already in use or if session creation fails.
    pub async fn create_session_optional_id(
        &self,
        session_id: Option<u32>,
    ) -> anyhow::Result<Session> {
        match session_id {
            Some(id) => self.create_session_with_id(id).await,
            None => self.create_session().await,
        }
    }

    /// Returns true if new sessions can be created on this connection
    #[allow(dead_code)] // Useful for callers to check before attempting to create sessions
    pub async fn can_create_sessions(&self) -> bool {
        self.inner.can_create_sessions().await
    }
}

/// Establishes a multiplexed TACACS+ connection using the given server config.
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection cannot be established
/// - TLS is requested but certificate/key are missing or invalid
/// - TLS handshake fails
pub async fn establish_connection(
    server: &ResolvedServer,
    options: &ConnectOptions,
) -> anyhow::Result<Connection> {
    let obfuscation_key = server.obfuscation_key();
    let stream = establish_stream(server, options).await?;

    let connection = Arc::new(TacacsConnection::new(obfuscation_key.as_deref()));
    connection
        .run(stream)
        .await
        .context("Failed to start connection handler")?;

    Ok(Connection { inner: connection })
}

/// Establishes a TCP or TLS stream based on the server config.
///
/// This is the shared connection-setup logic used by both
/// [`establish_connection`] (multiplexed sessions) and the dedicated
/// connection path (one-shot exchanges).
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection cannot be established
/// - TLS is requested but certificate/key are missing or invalid
/// - TLS handshake fails
pub async fn establish_stream(
    server: &ResolvedServer,
    options: &ConnectOptions,
) -> anyhow::Result<BoxedTransport> {
    config_connect::establish_stream(server, options).await
}
