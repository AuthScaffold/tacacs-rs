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
//! use tacacsrs_networking::tls_psk::{PskIdentity, connect_tls_psk};
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

pub use config_builder::PskConfigurationBuilder;

use openssl::ssl::{SslContext, SslMethod, SslVerifyMode, SslVersion};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

/// Represents a TLS 1.3 Pre-Shared Key identity and secret.
///
/// This holds the PSK identity string (sent to the server during handshake)
/// and the corresponding shared secret key. Both values must match what the
/// server expects.
///
/// # Security
///
/// The PSK key material is sensitive. Avoid logging or displaying it.
/// Use strong, randomly generated keys of sufficient length (at least 32 bytes
/// is recommended for TLS 1.3).
#[derive(Clone)]
pub struct PskIdentity {
    /// The identity string sent to the server during the TLS handshake.
    /// This allows the server to look up the correct pre-shared key.
    identity: String,

    /// The shared secret key bytes. Must match the server's configured key
    /// for the given identity.
    key: Vec<u8>,
}

impl PskIdentity {
    /// The minimum required key length in bytes.
    ///
    /// TLS 1.3 PSK requires keys of sufficient entropy. 16 bytes (128 bits) is
    /// the minimum recommended length.
    pub const MIN_KEY_LENGTH: usize = 16;

    /// Creates a new PSK identity with the given identity string and key.
    ///
    /// # Arguments
    ///
    /// * `identity` - A string identifying this client to the server (e.g., "tacacs-client-1").
    ///   Must not contain NUL (`\0`) bytes, as the identity is sent as a null-terminated
    ///   C string during the TLS handshake.
    /// * `key` - The shared secret key bytes. Must be at least [`Self::MIN_KEY_LENGTH`] bytes
    ///   (16 bytes / 128 bits).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `identity` contains a NUL byte (`\0`)
    /// - `identity` is empty
    /// - `key` is shorter than [`Self::MIN_KEY_LENGTH`] bytes
    ///
    /// # Example
    ///
    /// ```
    /// use tacacsrs_networking::tls_psk::PskIdentity;
    ///
    /// let psk = PskIdentity::new("my-client", b"super_secret_key!").unwrap();
    ///
    /// // NUL bytes in identity are rejected
    /// assert!(PskIdentity::new("bad\0id", b"super_secret_key!").is_err());
    ///
    /// // Keys shorter than 16 bytes are rejected
    /// assert!(PskIdentity::new("my-client", b"too_short").is_err());
    /// ```
    pub fn new(identity: impl Into<String>, key: impl Into<Vec<u8>>) -> anyhow::Result<Self> {
        let identity = identity.into();
        let key = key.into();

        if identity.is_empty() {
            anyhow::bail!("PSK identity must not be empty");
        }

        if identity.contains('\0') {
            anyhow::bail!(
                "PSK identity must not contain NUL bytes (identity is sent as a null-terminated C string)"
            );
        }

        if key.len() < Self::MIN_KEY_LENGTH {
            anyhow::bail!(
                "PSK key must be at least {} bytes, got {} bytes",
                Self::MIN_KEY_LENGTH,
                key.len()
            );
        }

        Ok(Self { identity, key })
    }

    /// Returns the PSK identity string.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Returns the PSK key bytes.
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl std::fmt::Debug for PskIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PskIdentity")
            .field("identity", &self.identity)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

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
/// use tacacsrs_networking::tls_psk::{PskIdentity, connect_tls_psk};
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
    let psk_identity = psk.identity.clone();
    let psk_key = psk.key.clone();

    ctx_builder.set_psk_client_callback(move |_ssl, _hint, identity_out, psk_out| {
        // Write the PSK identity (null-terminated C string)
        let identity_bytes = psk_identity.as_bytes();
        if identity_bytes.len() + 1 > identity_out.len() {
            log::error!(
                target: "tacacsrs_networking::tls_psk",
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
                target: "tacacsrs_networking::tls_psk",
                "PSK key buffer too small: need {} bytes, have {}",
                psk_key.len(),
                psk_out.len()
            );
            return Err(openssl::error::ErrorStack::get());
        }

        psk_out[..psk_key.len()].copy_from_slice(&psk_key);

        log::debug!(
            target: "tacacsrs_networking::tls_psk",
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
