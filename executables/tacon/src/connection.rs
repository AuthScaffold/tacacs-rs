use std::sync::Arc;

use tacacsrs_config::TacacsPlusServer;
use tacacsrs_config::prepare::PrepareOptions;
use tacacsrs_networking::{TacacsClient};
use tacacsrs_protocol::exchange::FixedExchange;

/// Represents an active TACACS+ connection (either plain TCP or TLS)
#[derive(Clone)]
pub struct Connection {
    inner: Arc<TacacsClient>,
    server_name: String,
}

impl Connection {
    pub(crate) const fn from_inner(inner: Arc<TacacsClient>, server_name: String) -> Self {
        Self { inner, server_name }
    }

    pub(crate) fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Executes one fixed TACACS+ request/reply exchange.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying exchange fails.
    pub async fn execute<Exchange>(&self, exchange: Exchange) -> anyhow::Result<Exchange::Reply>
    where
        Exchange: FixedExchange,
    {
        self.inner.execute(exchange).await
    }
}

/// Establishes a multiplexed TACACS+ connection using the given server configuration.
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection cannot be established
/// - TLS is requested but certificate/key are missing or invalid
/// - TLS handshake fails
pub async fn establish_connection(
    server: &TacacsPlusServer,
    options: PrepareOptions,
) -> anyhow::Result<Connection> {
    let endpoint = tacacsrs_config::prepare::prepare_endpoint(server, options)?;
    let connection = TacacsClient::connect_prepared(endpoint).await?;
    Ok(Connection::from_inner(Arc::new(connection), server.name.clone()))
}

/// Establishes a connection with TACACS+ single-connection mode disabled in
/// the effective server configuration.
///
/// Networking follows [`TacacsPlusServer::single_connection`] exactly, so the
/// CLI forces dedicated behavior by modifying a cloned server configuration before
/// handing it to [`TacacsClient`].
///
/// # Errors
///
/// Returns an error if the underlying connection cannot be established.
pub async fn establish_dedicated_connection(
    server: &TacacsPlusServer,
    options: PrepareOptions,
) -> anyhow::Result<Connection> {
    let mut dedicated_server = server.clone();
    dedicated_server.single_connection = false;
    establish_connection(&dedicated_server, options).await
}
