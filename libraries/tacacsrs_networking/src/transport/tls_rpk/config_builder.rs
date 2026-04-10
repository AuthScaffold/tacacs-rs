//! Builder for TLS RPK client configurations.
//!
//! This module uses OpenSSL 3.2+ native RPK support via direct FFI calls
//! to `SSL_CTX_set1_client_cert_type` and `SSL_CTX_set1_server_cert_type`,
//! since the Rust `openssl` crate does not yet wrap these APIs.

use std::os::raw::c_int;

use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use openssl_sys::SSL_CTX;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::rpk_identity::PinnedPublicKey;
use super::RpkIdentity;

// ---------------------------------------------------------------------------
// OpenSSL 3.2+ RPK FFI declarations (not yet in openssl-sys 0.9.x)
// ---------------------------------------------------------------------------

/// X.509 certificate type (RFC 7250 §3).
const TLSEXT_CERT_TYPE_X509: u8 = 0;
/// Raw public key certificate type (RFC 7250 §3).
const TLSEXT_CERT_TYPE_RPK: u8 = 2;

extern "C" {
    /// Sets the list of certificate types the client is willing to present
    /// at the context level.
    ///
    /// Corresponds to `SSL_CTX_set1_client_cert_type(3ssl)` (OpenSSL 3.2+).
    fn SSL_CTX_set1_client_cert_type(ctx: *mut SSL_CTX, val: *const u8, valsz: usize) -> c_int;

    /// Sets the list of certificate types the client will accept from the
    /// server at the context level.
    ///
    /// Corresponds to `SSL_CTX_set1_server_cert_type(3ssl)` (OpenSSL 3.2+).
    fn SSL_CTX_set1_server_cert_type(ctx: *mut SSL_CTX, val: *const u8, valsz: usize) -> c_int;
}

/// A builder for creating TLS connections authenticated with raw public keys.
///
/// Provides a fluent API for configuring RPK-based TLS connections with
/// options for SNI (Server Name Indication) and cipher suite selection.
///
/// # Example
///
/// ```no_run
/// use tacacsrs_networking::transport::tls_rpk::{RpkConfigurationBuilder, RpkIdentity, KeyFormat};
/// use tacacsrs_networking::helpers::connect_tcp;
///
/// # async fn example() -> anyhow::Result<()> {
/// let private_key_der: Vec<u8> = Vec::new(); // load your DER key here
/// let identity = RpkIdentity::new(private_key_der, KeyFormat::Pkcs8)?;
///
/// let tcp_stream = connect_tcp("tacacs.example.com:49").await?;
/// let tls_stream = RpkConfigurationBuilder::new(identity)
///     .with_server_name("tacacs.example.com")
///     .connect(tcp_stream)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct RpkConfigurationBuilder {
    identity: RpkIdentity,
    server_name: Option<String>,
    ciphersuites: Option<String>,
}

impl RpkConfigurationBuilder {
    /// Creates a new `RpkConfigurationBuilder` with the given RPK identity.
    ///
    /// # Arguments
    ///
    /// * `identity` - The raw public key identity to use for client authentication
    #[must_use]
    pub const fn new(identity: RpkIdentity) -> Self {
        Self {
            identity,
            server_name: None,
            ciphersuites: None,
        }
    }

    /// Sets the server name for SNI (Server Name Indication).
    ///
    /// # Arguments
    ///
    /// * `server_name` - The server hostname for SNI
    #[must_use]
    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = Some(server_name.into());
        self
    }

    /// Sets custom TLS 1.3 cipher suites.
    ///
    /// The default cipher suites are `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`.
    ///
    /// # Arguments
    ///
    /// * `ciphersuites` - Colon-separated list of TLS 1.3 cipher suite names
    #[must_use]
    pub fn with_ciphersuites(mut self, ciphersuites: impl Into<String>) -> Self {
        self.ciphersuites = Some(ciphersuites.into());
        self
    }

    /// Establishes a TLS connection using RPK client authentication.
    ///
    /// Uses OpenSSL 3.2+ native RPK support (RFC 7250) to negotiate raw
    /// public key exchange via the `client_certificate_type` and
    /// `server_certificate_type` TLS extensions.
    ///
    /// # Arguments
    ///
    /// * `stream` - The underlying TCP stream to wrap with TLS
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The OpenSSL SSL context cannot be created
    /// - The RPK cert-type negotiation fails (server may not support RPK)
    /// - The TLS handshake fails
    pub async fn connect(self, stream: TcpStream) -> anyhow::Result<SslStream<TcpStream>> {
        let ssl_context = create_rpk_ssl_context(&self.identity, self.ciphersuites.as_deref())?;

        let mut ssl = Ssl::new(&ssl_context)?;

        // Set SNI if configured
        if let Some(ref server_name) = self.server_name {
            ssl.set_hostname(server_name)?;
        }

        let mut tls_stream = SslStream::new(ssl, stream)?;

        tokio_openssl::SslStream::connect(std::pin::Pin::new(&mut tls_stream)).await?;

        log::info!(
            target: module_path!(),
            "TLS RPK connection established"
        );

        Ok(tls_stream)
    }
}

/// Creates an OpenSSL `SslContext` configured for TLS with RPK client
/// authentication using native RFC 7250 support (OpenSSL 3.2+).
///
/// The private key is loaded into the context and the `client_certificate_type`
/// and `server_certificate_type` extensions are configured to prefer RPK
/// with X.509 as fallback.  OpenSSL extracts the `SubjectPublicKeyInfo`
/// from the private key and sends it as the raw public key during the TLS
/// handshake.
fn create_rpk_ssl_context(
    identity: &RpkIdentity,
    ciphersuites: Option<&str>,
) -> anyhow::Result<SslContext> {
    let pkey = identity.to_openssl_pkey()?;

    let mut ctx_builder = SslContext::builder(SslMethod::tls_client())?;

    // Restrict to TLS 1.3
    ctx_builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Load the private key — OpenSSL derives the public key (SPKI) from it
    ctx_builder.set_private_key(&pkey)?;

    // Configure RFC 7250 RPK cert-type extensions via FFI.
    //
    // `SslContextBuilder::as_ptr()` is a public method that returns a valid
    // `*mut SSL_CTX`.  The `SSL_CTX_set1_*` functions copy the input buffer
    // and do not store a reference to it, so it is safe to pass a temporary
    // slice.
    let client_types = [TLSEXT_CERT_TYPE_RPK, TLSEXT_CERT_TYPE_X509];
    let server_types = [TLSEXT_CERT_TYPE_RPK, TLSEXT_CERT_TYPE_X509];

    let ret = unsafe {
        SSL_CTX_set1_client_cert_type(
            ctx_builder.as_ptr(),
            client_types.as_ptr(),
            client_types.len(),
        )
    };
    if ret != 1 {
        anyhow::bail!("SSL_CTX_set1_client_cert_type failed (OpenSSL 3.2+ required for RPK)");
    }

    let ret = unsafe {
        SSL_CTX_set1_server_cert_type(
            ctx_builder.as_ptr(),
            server_types.as_ptr(),
            server_types.len(),
        )
    };
    if ret != 1 {
        anyhow::bail!("SSL_CTX_set1_server_cert_type failed (OpenSSL 3.2+ required for RPK)");
    }

    // Configure server verification
    let pinned_keys: Vec<PinnedPublicKey> = identity.pinned_server_keys().to_vec();
    if pinned_keys.is_empty() {
        // No pinned keys — disable server certificate verification.
        ctx_builder.set_verify(SslVerifyMode::NONE);
    } else {
        // Verify the server's public key against pinned keys.
        ctx_builder.set_verify_callback(SslVerifyMode::PEER, move |_preverify_ok, ctx| {
            // Only check the leaf (depth 0).
            if ctx.error_depth() != 0 {
                return true;
            }

            let Some(cert) = ctx.current_cert() else {
                log::warn!(target: module_path!(), "No server certificate in handshake");
                return false;
            };

            let server_pubkey_der = match cert.public_key() {
                Ok(pkey) => match pkey.public_key_to_der() {
                    Ok(der) => der,
                    Err(e) => {
                        log::warn!(
                            target: module_path!(),
                            "Failed to extract server public key DER: {e}"
                        );
                        return false;
                    }
                },
                Err(e) => {
                    log::warn!(
                        target: module_path!(),
                        "Failed to extract server public key: {e}"
                    );
                    return false;
                }
            };

            for pinned in &pinned_keys {
                if server_pubkey_der == pinned.spki_der {
                    log::debug!(
                        target: module_path!(),
                        "Server public key matches pinned key '{}'",
                        pinned.name,
                    );
                    return true;
                }
            }

            log::warn!(
                target: module_path!(),
                "Server public key does not match any pinned RPK"
            );
            false
        });
    }

    // Set TLS 1.3 ciphersuites
    let ciphersuites = ciphersuites.unwrap_or("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
    ctx_builder.set_ciphersuites(ciphersuites)?;

    Ok(ctx_builder.build())
}
