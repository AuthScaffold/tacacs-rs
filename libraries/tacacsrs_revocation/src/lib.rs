//! CRL-based revocation checks for TACACS+ over TLS server certificates.
//!
//! [`CrlVerifier`] implements the [`tacacsrs_networking::RevocationVerifier`]
//! contract. The TLS handshake calls the verifier once for each new
//! connection. The verifier never closes an established connection.
//!
//! The verifier reads the CRL distribution points of each non-anchor
//! certificate in the verified path. It fetches only `http://` URLs that the
//! allowlist in [`tacacsrs_networking::RevocationSettings`] permits. It
//! verifies each CRL signature with the key of the issuer certificate in the
//! path, checks the CRL scope, and applies delta CRLs.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use tacacsrs_networking::{RevocationNetwork, RevocationSettings, RevocationVerifier};
//! use tacacsrs_revocation::CrlVerifier;
//!
//! # async fn example() {
//! let (_sender, receiver) = tokio::sync::watch::channel(RevocationSettings::default());
//! let verifier = CrlVerifier::new(receiver);
//! let refresh = verifier.spawn_refresh(RevocationNetwork::default());
//! let shared: Arc<dyn RevocationVerifier> = Arc::new(verifier.clone());
//! # drop(shared);
//! # refresh.abort();
//! # }
//! ```

mod address;
mod certificate;
mod crl;
mod der;
mod disk;
mod evaluate;
mod fetch;
mod store;
#[cfg(test)]
mod tests;
mod verifier;

#[doc(inline)]
pub use verifier::{CrlVerifier, CrlVerifierCounters};
