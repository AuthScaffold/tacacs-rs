//! Thin transport dispatcher that selects the appropriate transport backend
//! for a [`TacacsPlusServer`] configuration and establishes a stream.
//!
//! This module deliberately does **not** know how to parse certificates,
//! private keys, or PSK material. Each transport backend (the crate-internal
//! `transport::tls` and `transport::tls_psk` modules) owns its own
//! translation from [`TacacsPlusServer`] to a connected stream. The dispatcher
//! is only responsible for:
//!
//! - opening the TCP connection (with optional timeout),
//! - choosing which backend handles the connection, and
//! - boxing the resulting stream as a [`BoxedTransport`].
//!
//! This is the single entry point used by both `tacon` and the
//! `tacacsrs_agent` daemon when they need to talk to an upstream TACACS+
//! server.

use std::time::Duration;

use anyhow::{Context, Result};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_credential_resolution::RuntimeServer;

use crate::helpers::connect_tcp;
use crate::transport::BoxedTransport;

/// Options that control connection behaviour beyond what the
/// [`TacacsPlusServer`] already carries.
///
/// TACACS+ single-connection mode is intentionally controlled by
/// [`TacacsPlusServer::single_connection`]. Callers that need dedicated mode
/// should pass a server value with `single_connection` set to `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectPreflight {
    /// Do not perform any connection preflight when constructing a client.
    #[default]
    Disabled,
    /// Send a TACACS+ accounting WATCHDOG request before returning the client.
    ///
    /// When the server configuration enables single-connection mode, this also
    /// discovers support and promotes the preflight stream if the server echoes
    /// the single-connect flag.
    AccountingWatchdog,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Dangerously disable TLS certificate verification.
    disable_certificate_verification: bool,
    /// Connection timeout. When `None`, no timeout is applied to the TCP
    /// connect phase — callers are responsible for their own timeouts.
    timeout: Option<Duration>,
    /// Optional preflight operation performed by `TacacsClient::connect`.
    preflight: ConnectPreflight,
}

impl ConnectOptions {
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

/// Establishes a transport stream to the server described by `server`.
///
/// The transport type is selected based on the resolved server configuration:
///
/// | Configuration | Transport |
/// |---------------|-----------|
/// | `client-identity.tls13-epsk` | TLS 1.3 PSK (feature-gated) |
/// | `client-identity.certificate` or `server-authentication` | mTLS / TLS |
/// | `shared-secret` only | Plain TCP |
/// | no TLS fields and no `shared-secret` | Plain TCP without TACACS+ obfuscation |
///
/// The actual interpretation of the TLS / PSK fields lives in the owning
/// transport backend — this function only routes between them.
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection fails or times out
/// - the selected backend rejects the configured material or fails to
///   complete its handshake
pub(crate) async fn establish_stream(
    runtime: std::sync::Arc<RuntimeServer>,
    options: &ConnectOptions,
) -> Result<BoxedTransport> {
    let server = runtime.config();
    let address = server.socket_address();

    let security_label = security_label(server);
    log::debug!(
        "Connecting to TACACS+ server {address} (security: {security_label}, timeout: {:?})",
        options.timeout,
    );

    let tcp_stream = match options.timeout {
        Some(dur) => tokio::time::timeout(dur, connect_tcp(&address))
            .await
            .with_context(|| format!("Timed out connecting to {address}"))?
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?,
        None => connect_tcp(&address)
            .await
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?,
    };

    log::debug!("TCP connection to {address} established");

    // TLS-PSK must be checked before general TLS because `is_tls()` also
    // returns true when only PSK material is configured.
    if crate::transport::tls_psk::server_has_psk(server) {
        let stream =
            crate::transport::tls_psk::establish_from_server(runtime, &address, tcp_stream).await?;
        return Ok(BoxedTransport::new(stream));
    }

    if server.is_tls() {
        let stream = crate::transport::tls::establish_from_server(
            server,
            &address,
            tcp_stream,
            options.disable_certificate_verification,
        )
        .await?;
        return Ok(BoxedTransport::new(stream));
    }

    // Plain TCP, with optional TACACS+ body obfuscation handled by the packet layer.
    Ok(BoxedTransport::new(tcp_stream))
}

fn security_label(server: &TacacsPlusServer) -> &'static str {
    if server.is_tls() {
        "tls"
    } else if server.is_obfuscation() {
        "obfuscation"
    } else {
        "plain-tcp"
    }
}
