//! Establishes connections from prepared endpoint values.
//!
//! The dispatcher uses prepared transport values without interpreting configuration.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::endpoint::PreparedEndpoint;
use crate::helpers::connect_tcp;
use crate::transport::BoxedTransport;
use crate::transport::{tls, tls_psk};

#[derive(Clone)]
pub(crate) enum PreparedTransport {
    Tcp,
    Tls(tls::TlsClientConfig),
    Psk(tls_psk::PskClientConfig, Option<String>),
}

/// Optional readiness check before a prepared client is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectPreflight {
    /// Do not run a connection preflight when constructing a client.
    #[default]
    Disabled,
    /// Send a TACACS+ accounting WATCHDOG request before returning the client.
    ///
    /// When the server configuration enables single-connection mode, this also
    /// discovers support and promotes the preflight connection if the server echoes
    /// the single-connect flag.
    AccountingWatchdog,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Disables TLS certificate verification.
    disable_certificate_verification: bool,
    /// Connection timeout. When `None`, no timeout is applied to the TCP
    /// connection phase. Callers must apply other timeouts.
    timeout: Option<Duration>,
    /// Optional preflight operation performed by `TacacsClient::connect_prepared`.
    preflight: ConnectPreflight,
}

impl ConnectOptions {
    pub(crate) const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub(crate) const fn certificate_verification_disabled(&self) -> bool {
        self.disable_certificate_verification
    }

    /// Returns options with TLS certificate verification disabled when
    /// `disabled` is true.
    #[must_use]
    pub const fn with_certificate_verification_disabled(mut self, disabled: bool) -> Self {
        self.disable_certificate_verification = disabled;
        self
    }

    /// Returns options with the TCP connect timeout set to `timeout`.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Returns options with the connection preflight mode set to `preflight`.
    #[must_use]
    pub const fn with_preflight(mut self, preflight: ConnectPreflight) -> Self {
        self.preflight = preflight;
        self
    }

    pub(crate) const fn preflight(&self) -> ConnectPreflight {
        self.preflight
    }
}

/// Opens the prepared transport without interpreting source configuration.
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection fails or times out
/// - the prepared backend fails to complete its handshake
pub(crate) async fn establish_stream(endpoint: &PreparedEndpoint) -> Result<BoxedTransport> {
    let address = endpoint.address();
    let options = &endpoint.options;

    let security_label = endpoint.security_label();
    log::debug!(
        "Connecting to TACACS+ server {address} (security: {security_label}, timeout: {:?})",
        options.timeout,
    );

    let tcp_stream = match options.timeout {
        Some(dur) => tokio::time::timeout(dur, connect_tcp(address))
            .await
            .with_context(|| format!("Connection to TACACS+ server {address} timed out"))?
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?,
        None => connect_tcp(address)
            .await
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?,
    };

    log::debug!("TCP connection to {address} established");

    match &endpoint.transport {
        PreparedTransport::Tcp => Ok(BoxedTransport::new(tcp_stream)),
        PreparedTransport::Tls(config) => {
            Ok(BoxedTransport::new(config.connect(tcp_stream).await?))
        }
        PreparedTransport::Psk(config, server_name) => Ok(BoxedTransport::new(
            config
                .connect(address, server_name.as_deref(), tcp_stream)
                .await?,
        )),
    }
}
