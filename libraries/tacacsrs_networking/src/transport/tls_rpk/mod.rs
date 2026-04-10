//! TLS Raw Public Key (RPK) client authentication support.
//!
//! This module provides TLS client authentication using raw public keys
//! as described by RFC 7250, implemented via OpenSSL 3.2+ native RPK.
//! RPK authentication allows a client to prove possession of a private
//! key without requiring a full X.509 certificate chain.
//!
//! # Implementation
//!
//! Uses OpenSSL's `SSL_set1_client_cert_type()` and
//! `SSL_set1_server_cert_type()` APIs (OpenSSL 3.2+) via direct FFI
//! calls, since the Rust `openssl` crate does not yet wrap them.
//! The `client_certificate_type` and `server_certificate_type` TLS
//! extensions are negotiated with RPK preferred and X.509 as fallback.
//!
//! Server verification (when configured) works by comparing the server's
//! public key against the `raw-public-keys` defined in the YANG
//! configuration.
//!
//! # Example
//!
//! ```no_run
//! use tacacsrs_networking::transport::tls_rpk::{RpkConfigurationBuilder, RpkIdentity, KeyFormat};
//! use tacacsrs_networking::helpers::connect_tcp;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let private_key_der: Vec<u8> = Vec::new(); // load your DER key here
//! let identity = RpkIdentity::new(private_key_der, KeyFormat::Pkcs8)?;
//!
//! let tcp_stream = connect_tcp("tacacs.example.com:49").await?;
//! let tls_stream = RpkConfigurationBuilder::new(identity)
//!     .with_server_name("tacacs.example.com")
//!     .connect(tcp_stream)
//!     .await?;
//! # Ok(())
//! # }
//! ```

// The workspace forbids `unsafe_code`, but the config_builder requires FFI
// calls to OpenSSL 3.2+ RPK APIs not yet exposed by the `openssl` crate.
#[allow(unsafe_code)]
mod config_builder;
mod rpk_identity;

// Provide the Transport impl for SslStream<TcpStream> when the `psk`
// feature is not also enabled (the `psk` feature already provides this
// impl via its own `tls_psk` module).
#[cfg(not(feature = "psk"))]
mod transport_impl;

pub use config_builder::RpkConfigurationBuilder;
pub use rpk_identity::{KeyFormat, PinnedPublicKey, RpkIdentity};
