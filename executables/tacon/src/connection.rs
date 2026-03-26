use std::sync::Arc;

use anyhow::Context;
use tacacsrs_config::{ResolvedSecurity, ServerConnectionConfig};
use tacacsrs_networking::{
    connection::TacacsConnection, helpers::tls_server_name, session::Session,
    traits::SessionManagementTrait, transport::tls::TlsConfigurationBuilder, BoxedTransport,
};
#[cfg(feature = "psk")]
use tacacsrs_networking::transport::tls_psk::{PskConfigurationBuilder, PskIdentity};

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
pub async fn establish_connection(server: &ServerConnectionConfig) -> anyhow::Result<Connection> {
    let obfuscation_key = obfuscation_key_bytes(&server.security);
    let stream = establish_stream(server).await?;

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
pub async fn establish_stream(server: &ServerConnectionConfig) -> anyhow::Result<BoxedTransport> {
    let address = server.socket_address();
    let tcp_stream = tacacsrs_networking::helpers::connect_tcp(&address)
        .await
        .context("Failed to establish TCP connection")?;

    match &server.security {
        ResolvedSecurity::Obfuscation { .. } => Ok(BoxedTransport::new(tcp_stream)),

        #[cfg(feature = "psk")]
        ResolvedSecurity::Psk { identity, key } => {
            let psk =
                PskIdentity::new(identity, key.as_bytes()).context("Invalid PSK credentials")?;
            let tls_stream = PskConfigurationBuilder::new(psk)
                .connect(tcp_stream)
                .await
                .context("Failed to establish TLS PSK connection")?;
            Ok(BoxedTransport::new(tls_stream))
        }

        #[cfg(not(feature = "psk"))]
        ResolvedSecurity::Psk { .. } => {
            anyhow::bail!("PSK support is not enabled; rebuild with the `psk` feature flag")
        }

        ResolvedSecurity::Tls {
            client_certificate,
            client_key,
            ca_cert_files: _,
            insecure_disable_certificate_verification,
        } => {
            let client_cert = client_certificate
                .as_ref()
                .context("TLS requires a client certificate or PSK credentials")?;
            let key = client_key
                .as_ref()
                .context("TLS requires a client key or PSK credentials")?;

            let tls_config = Arc::new(
                TlsConfigurationBuilder::new()
                    .with_client_auth_cert_files(client_cert, key)
                    .await
                    .context("Failed to load TLS certificates")?
                    .with_certificate_verification_disabled(
                        *insecure_disable_certificate_verification,
                    )
                    .build()
                    .context("Failed to build TLS configuration")?,
            );

            let tls_stream = tacacsrs_networking::transport::tls::connect_tls(
                &tls_config,
                tcp_stream,
                tls_server_name(&address),
            )
            .await
            .context("Failed to establish TLS connection")?;

            Ok(BoxedTransport::new(tls_stream))
        }
    }
}

/// Extracts the obfuscation key bytes from a [`ResolvedSecurity`] variant.
///
/// Returns `Some(key_bytes)` only for [`ResolvedSecurity::Obfuscation`] with a
/// non-empty shared secret; all other variants return `None`.
pub(crate) fn obfuscation_key_bytes(security: &ResolvedSecurity) -> Option<Vec<u8>> {
    match security {
        ResolvedSecurity::Obfuscation { shared_secret } => {
            shared_secret.as_ref().map(|s| s.as_bytes().to_vec())
        }
        _ => None,
    }
}
