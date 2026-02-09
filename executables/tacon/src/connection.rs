use std::sync::Arc;

use anyhow::Context;
use tacacsrs_networking::{
    session::Session, connection::TacacsConnection, tls::TlsConfigurationBuilder,
    traits::SessionManagementTrait, SingleConnectionState,
};

use crate::cli::Cli;

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

    /// Returns the current single connection state
    pub async fn single_connection_state(&self) -> SingleConnectionState {
        self.inner.single_connection_state().await
    }

    /// Returns true if new sessions can be created on this connection
    #[allow(dead_code)] // Useful for callers to check before attempting to create sessions
    pub async fn can_create_sessions(&self) -> bool {
        self.inner.can_create_sessions().await
    }
}

/// Establishes a connection to the TACACS+ server
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection cannot be established
/// - TLS is requested but certificate/key are missing or invalid
/// - TLS handshake fails
pub async fn establish_connection(cli: &Cli) -> anyhow::Result<Connection> {
    let obfuscation_key = cli.obfuscation_key.as_ref().map(String::as_bytes);
    let tcp_stream = tacacsrs_networking::helpers::connect_tcp(&cli.server_addr)
        .await
        .context("Failed to establish TCP connection")?;

    let connection = Arc::new(TacacsConnection::new(obfuscation_key));

    if cli.use_tls {
        let client_cert = cli
            .client_certificate
            .as_ref()
            .context("TLS requires a client certificate")?;
        let client_key = cli
            .client_key
            .as_ref()
            .context("TLS requires a client key")?;

        let tls_config = Arc::new(
            TlsConfigurationBuilder::new()
                .with_client_auth_cert_files(client_cert, client_key)
                .await
                .context("Failed to load TLS certificates")?
                .with_certificate_verification_disabled(true)
                .build()
                .context("Failed to build TLS configuration")?,
        );

        let tls_stream =
            tacacsrs_networking::tls::connect_tls(&tls_config, tcp_stream, "tacacsserver.local")
                .await
                .context("Failed to establish TLS connection")?;

        connection
            .run(tls_stream)
            .await
            .context("Failed to start TLS connection handler")?;
    } else {
        connection
            .run(tcp_stream)
            .await
            .context("Failed to start TCP connection handler")?;
    }

    Ok(Connection { inner: connection })
}
