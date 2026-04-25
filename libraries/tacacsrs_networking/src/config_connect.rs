//! Thin transport dispatcher that selects the appropriate transport backend
//! for a [`TacacsPlusServer`] configuration and establishes a stream.
//!
//! This module deliberately does **not** know how to parse certificates,
//! private keys, or PSK material. Each transport backend
//! ([`crate::transport::tls`], [`crate::transport::tls_psk`]) owns its own
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

use crate::BoxedTransport;
use crate::helpers::connect_tcp;

/// Options that control connection behaviour beyond what the
/// [`TacacsPlusServer`] already carries.
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Dangerously disable TLS certificate verification.
    pub disable_certificate_verification: bool,
    /// Connection timeout. When `None`, no timeout is applied to the TCP
    /// connect phase — callers are responsible for their own timeouts.
    pub timeout: Option<Duration>,
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
pub async fn establish_stream(
    server: &TacacsPlusServer,
    options: &ConnectOptions,
) -> Result<BoxedTransport> {
    let address = server.socket_address();

    let security_label = if server.is_tls() {
        "tls"
    } else {
        "obfuscation"
    };
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
    #[cfg(feature = "psk")]
    if crate::transport::tls_psk::server_has_psk(server) {
        let stream =
            crate::transport::tls_psk::establish_from_server(server, &address, tcp_stream).await?;
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

    // Plain TCP (obfuscation mode)
    Ok(BoxedTransport::new(tcp_stream))
}
