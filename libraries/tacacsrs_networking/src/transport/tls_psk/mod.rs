//! TLS 1.3 Pre-Shared Key (PSK) support for TACACS+ connections.
//!
//! This module provides TLS 1.3 with out-of-band PSK authentication using OpenSSL,
//! as an alternative to certificate-based TLS authentication. This is useful in
//! environments where managing PKI infrastructure is impractical, and both the
//! client and server share a pre-configured secret key and identity.
//!
//! # Overview
//!
//! TLS 1.3 PSK (RFC 8446 §2.2) allows a client and server to authenticate using
//! a shared secret rather than certificates. This module implements the "external PSK"
//! variant, where the PSK identity and key are provisioned out-of-band (i.e., configured
//! ahead of time on both endpoints).
//!
//! # Example
//!
//! ```no_run
//! use tacacsrs_networking::transport::tls_psk::{PskIdentity, connect_tls_psk};
//! use tacacsrs_networking::helpers::connect_tcp;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let psk = PskIdentity::new("my-tacacs-client", b"shared_secret_key_here!!")?;
//!
//! let tcp_stream = connect_tcp("tacacs.example.com:49").await?;
//! let tls_stream = connect_tls_psk(tcp_stream, &psk).await?;
//! # Ok(())
//! # }
//! ```

mod config_builder;
mod psk_identity;
#[allow(clippy::module_inception)]
mod tls_psk;

pub use config_builder::PskConfigurationBuilder;
pub use psk_identity::PskIdentity;

use openssl::ssl::{SslContext, SslMethod, SslVerifyMode, SslVersion};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

/// Establishes a TLS 1.3 PSK connection over an existing TCP stream.
///
/// This is a convenience function that creates a [`PskConfigurationBuilder`]
/// with default settings and connects using the provided PSK identity.
///
/// # Arguments
///
/// * `stream` - The underlying TCP stream
/// * `psk` - The pre-shared key identity and secret
///
/// # Errors
///
/// Returns an error if:
/// - The OpenSSL context cannot be created
/// - The TLS handshake fails (e.g., PSK mismatch, server doesn't support PSK)
///
/// # Example
///
/// ```no_run
/// use tacacsrs_networking::transport::tls_psk::{PskIdentity, connect_tls_psk};
/// use tacacsrs_networking::helpers::connect_tcp;
///
/// # async fn example() -> anyhow::Result<()> {
/// let psk = PskIdentity::new("client1", b"shared_key_at_least_16")?;
/// let tcp = connect_tcp("tacacs.example.com:49").await?;
/// let tls = connect_tls_psk(tcp, &psk).await?;
/// # Ok(())
/// # }
/// ```
pub async fn connect_tls_psk(
    stream: TcpStream,
    psk: &PskIdentity,
) -> anyhow::Result<SslStream<TcpStream>> {
    PskConfigurationBuilder::new(psk.clone())
        .connect(stream)
        .await
}

/// Creates an OpenSSL `SslContext` configured for TLS 1.3 PSK.
///
/// This is used internally by [`PskConfigurationBuilder`] but can also be used
/// directly for advanced configuration scenarios.
///
/// # Arguments
///
/// * `psk` - The pre-shared key identity and secret
/// * `ciphersuites` - Optional TLS 1.3 ciphersuites override. If `None`, defaults
///   to `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`.
fn create_psk_ssl_context(
    psk: &PskIdentity,
    ciphersuites: Option<&str>,
) -> anyhow::Result<SslContext> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls_client())?;

    // Restrict to TLS 1.3 only
    ctx_builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // For PSK-only mode, we don't verify server certificates
    ctx_builder.set_verify(SslVerifyMode::NONE);

    // Set the PSK client callback
    let psk_identity = psk.identity().to_owned();
    let psk_key = psk.key().to_vec();

    ctx_builder.set_psk_client_callback(move |_ssl, _hint, identity_out, psk_out| {
        // Write the PSK identity (null-terminated C string)
        let identity_bytes = psk_identity.as_bytes();
        if identity_bytes.len() + 1 > identity_out.len() {
            log::error!(
                target: module_path!(),
                "PSK identity buffer too small: need {} bytes, have {}",
                identity_bytes.len() + 1,
                identity_out.len()
            );
            return Err(openssl::error::ErrorStack::get());
        }

        identity_out[..identity_bytes.len()].copy_from_slice(identity_bytes);
        identity_out[identity_bytes.len()] = 0; // null terminator

        // Write the PSK key
        if psk_key.len() > psk_out.len() {
            log::error!(
                target: module_path!(),
                "PSK key buffer too small: need {} bytes, have {}",
                psk_key.len(),
                psk_out.len()
            );
            return Err(openssl::error::ErrorStack::get());
        }

        psk_out[..psk_key.len()].copy_from_slice(&psk_key);

        log::debug!(
            target: module_path!(),
            "Provided PSK for TLS 1.3 handshake (identity: {})",
            std::str::from_utf8(identity_bytes).unwrap_or("<invalid utf8>")
        );

        Ok(psk_key.len())
    });

    // Set TLS 1.3 ciphersuites compatible with PSK
    let ciphersuites = ciphersuites.unwrap_or("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
    ctx_builder.set_ciphersuites(ciphersuites)?;

    Ok(ctx_builder.build())
}
