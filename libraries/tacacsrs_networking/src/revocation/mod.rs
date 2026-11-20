//! Injected certificate revocation checks for certificate TLS connections.
//!
//! This module defines the contract between the TLS handshake and a host-owned
//! revocation verifier. The networking crate does not fetch, cache, or interpret
//! revocation evidence. A host attaches a [`RevocationVerifier`] to a
//! [`PreparedEndpoint`](crate::PreparedEndpoint) or
//! [`NativeConnector`](crate::routed::NativeConnector). The handshake then asks the
//! verifier for a [`RevocationDecision`] after the normal path, host name, and
//! trust checks pass.
//!
//! Revocation is checked only when a connection is established. No code in
//! this crate closes an established connection because evidence expires, a
//! refresh fails, or the policy changes.
//!
//! When the verifier reports [`RevocationDecision::NeedEvidence`], the handshake
//! pauses before the client sends its certificate. The handshake waits for
//! [`RevocationVerifier::obtain`] and then runs the verify step again on the same
//! socket.

mod pattern;
#[cfg(test)]
mod tests_handshake;

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use openssl::x509::X509;

use crate::endpoint::ConnectionGuard;

pub use pattern::{DistributionPointPattern, DistributionPointUrl};

/// Default time that `soft-fail` accepts a CRL after its `nextUpdate`.
pub const DEFAULT_SOFT_FAIL_GRACE: Duration = Duration::from_secs(86_400);

/// Default limit for one CRL fetch, including DNS, connect, and body.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Default size limit for one fetched CRL.
pub const DEFAULT_MAX_CRL_BYTES: u64 = 16 * 1024 * 1024;

/// How a missing, stale, or listed revocation status affects a new connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum RevocationEnforcement {
    /// Do not check revocation.
    #[default]
    Disabled,
    /// Accept a server only with fresh evidence that lists no certificate in its path.
    HardFail,
    /// Like `HardFail`, but accept a validated CRL for a grace period after its `nextUpdate`.
    SoftFail,
    /// Reject a listed certificate. Accept the server and warn when evidence is unavailable.
    WarnOnly,
}

impl RevocationEnforcement {
    /// Returns whether a verifier must be attached to certificate TLS connections.
    #[must_use]
    pub const fn requires_verifier(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Returns the YANG enumeration name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::HardFail => "hard-fail",
            Self::SoftFail => "soft-fail",
            Self::WarnOnly => "warn-only",
        }
    }
}

impl fmt::Display for RevocationEnforcement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Global CRL revocation policy, published to a verifier at runtime.
///
/// The policy is plain data. It is not stored on prepared endpoints, so a policy
/// change affects only new connections and never retires an established one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RevocationSettings {
    /// Enforcement mode.
    pub enforcement: RevocationEnforcement,
    /// Time after a CRL's original `nextUpdate` during which `SoftFail` accepts it.
    pub soft_fail_grace: Duration,
    /// URL patterns that the verifier may fetch CRLs from.
    pub allowed_distribution_points: Vec<DistributionPointPattern>,
    /// Exact CRL URLs to fetch before any connection needs them.
    pub prefetch_distribution_points: Vec<DistributionPointUrl>,
    /// Allows fetches to RFC 1918 and unique local addresses.
    pub allow_private_addresses: bool,
    /// Limit for one CRL fetch, including DNS, connect, and the complete body.
    pub fetch_timeout: Duration,
    /// Size limit for one fetched CRL.
    pub max_crl_bytes: u64,
    /// Optional directory for a persistent CRL cache.
    pub cache_directory: Option<PathBuf>,
}

impl Default for RevocationSettings {
    fn default() -> Self {
        Self {
            enforcement: RevocationEnforcement::Disabled,
            soft_fail_grace: DEFAULT_SOFT_FAIL_GRACE,
            allowed_distribution_points: Vec::new(),
            prefetch_distribution_points: Vec::new(),
            allow_private_addresses: true,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            max_crl_bytes: DEFAULT_MAX_CRL_BYTES,
            cache_directory: None,
        }
    }
}

impl RevocationSettings {
    /// Checks the relations between fields.
    ///
    /// # Errors
    ///
    /// Returns an error when enforcement is enabled without an allowed
    /// distribution point, when a prefetch URL matches no allowed pattern, when a
    /// duration or size is zero, or when the cache directory is relative.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.enforcement.requires_verifier() || !self.allowed_distribution_points.is_empty(),
            "Revocation enforcement {} requires at least one allowed distribution point",
            self.enforcement
        );
        ensure!(!self.soft_fail_grace.is_zero(), "The soft-fail grace period must be positive");
        ensure!(!self.fetch_timeout.is_zero(), "The CRL fetch timeout must be positive");
        ensure!(self.max_crl_bytes > 0, "The CRL size limit must be positive");
        for url in &self.prefetch_distribution_points {
            ensure!(
                self.allows(url),
                "Prefetch distribution point {url} matches no allowed distribution point"
            );
        }
        if let Some(directory) = &self.cache_directory {
            ensure!(directory.is_absolute(), "The CRL cache directory must be an absolute path");
        }
        Ok(())
    }

    /// Returns whether an allowed pattern matches `url`.
    #[must_use]
    pub fn allows(&self, url: &DistributionPointUrl) -> bool {
        self.allowed_distribution_points
            .iter()
            .any(|pattern| pattern.matches(url))
    }
}

/// A server certificate path that passed path, host name, and trust checks.
///
/// The certificates are in order from the leaf to the trust anchor. Clones share
/// the certificates.
#[derive(Clone)]
pub struct VerifiedPath {
    certificates: Arc<[X509]>,
    peer_identity: Arc<str>,
}

impl VerifiedPath {
    /// Creates a path from certificates in order from the leaf to the trust anchor.
    ///
    /// # Errors
    ///
    /// Returns an error when `certificates` is empty.
    pub fn new(certificates: Vec<X509>, peer_identity: &str) -> Result<Self> {
        ensure!(!certificates.is_empty(), "A verified certificate path is empty");
        Ok(Self {
            certificates: certificates.into(),
            peer_identity: peer_identity.into(),
        })
    }

    /// Returns the certificates from the leaf to the trust anchor.
    #[must_use]
    pub fn certificates(&self) -> &[X509] {
        &self.certificates
    }

    /// Returns the server certificate.
    #[must_use]
    pub fn leaf(&self) -> &X509 {
        &self.certificates[0]
    }

    /// Returns the DNS name or IP address that the server certificate matched.
    #[must_use]
    pub fn peer_identity(&self) -> &str {
        &self.peer_identity
    }
}

impl fmt::Debug for VerifiedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPath")
            .field("peer_identity", &self.peer_identity)
            .field("length", &self.certificates.len())
            .finish()
    }
}

/// The result of one synchronous revocation lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationDecision {
    /// Fresh evidence shows that no certificate in the path is revoked.
    Verified,
    /// The policy accepts the path without fresh evidence. The reason is logged and counted.
    Accept(String),
    /// The policy rejects the path.
    Reject(RevocationRejection),
    /// The verifier has no usable evidence and can try to obtain it.
    NeedEvidence,
}

/// Why a verifier rejected a certificate path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRejection {
    reason: String,
    revoked: bool,
}

impl RevocationRejection {
    /// A CRL lists a certificate in the path.
    #[must_use]
    pub fn revoked(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            revoked: true,
        }
    }

    /// Evidence is missing, stale, or invalid, and the policy requires it.
    #[must_use]
    pub fn unverified(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            revoked: false,
        }
    }

    /// Returns the reason for logs and errors.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns whether a CRL lists a certificate in the path.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
}

/// Host-owned revocation checks for new certificate TLS connections.
///
/// `decide` runs inside the OpenSSL verify callback on the async worker. It must
/// do only an in-memory lookup. It must not block, perform I/O, or verify CRL
/// signatures. `obtain` runs after the handshake pauses. It can fetch and
/// validate evidence, but it must move CPU-heavy work off the async worker.
#[async_trait]
pub trait RevocationVerifier: Send + Sync {
    /// Returns the current decision for a verified path.
    fn decide(&self, path: &VerifiedPath) -> RevocationDecision;

    /// Tries to obtain evidence for `path` through `network` before `deadline`.
    ///
    /// The handshake calls [`Self::decide`] again after this method returns. A
    /// verifier that cannot obtain evidence must make the next `decide` call
    /// return `Accept` or `Reject`. A second `NeedEvidence` rejects the server.
    async fn obtain(
        &self,
        path: &VerifiedPath,
        network: &RevocationNetwork,
        deadline: Option<tokio::time::Instant>,
    );
}

/// The local network context of one server, used to fetch its revocation evidence.
///
/// Fetches use the same local binding and connection guard as the TACACS+
/// connection. They never fall back to an unbound connection.
#[derive(Clone, Default)]
pub struct RevocationNetwork {
    binding: crate::LocalBinding,
    guard: Option<Arc<dyn ConnectionGuard>>,
}

impl RevocationNetwork {
    /// Creates a context from a local binding and an optional host guard.
    #[must_use]
    pub fn new(binding: crate::LocalBinding, guard: Option<Arc<dyn ConnectionGuard>>) -> Self {
        Self { binding, guard }
    }

    /// Returns the local binding.
    #[must_use]
    pub fn binding(&self) -> &crate::LocalBinding {
        &self.binding
    }

    /// Opens a TCP connection to `host` and `port` with this binding and guard.
    ///
    /// `filter` checks each resolved address before the connection attempt. A
    /// rejected address fails the connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the host name is invalid, resolution fails, `filter`
    /// or the guard rejects an address, or no address accepts the connection.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        filter: &(dyn Fn(SocketAddr) -> Result<()> + Send + Sync),
    ) -> Result<tokio::net::TcpStream> {
        let address = crate::ServerAddress::new(host, port)
            .with_context(|| format!("Invalid CRL distribution point host {host}"))?;
        let guard = FilteredGuard {
            filter,
            guard: self.guard.as_deref(),
        };
        crate::destination::connect_tcp(&address, Some(&guard), &self.binding).await
    }
}

impl fmt::Debug for RevocationNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevocationNetwork")
            .field("binding", &self.binding)
            .field("guard", &self.guard.is_some())
            .finish()
    }
}

struct FilteredGuard<'a> {
    filter: &'a (dyn Fn(SocketAddr) -> Result<()> + Send + Sync),
    guard: Option<&'a dyn ConnectionGuard>,
}

impl ConnectionGuard for FilteredGuard<'_> {
    fn check_destination(&self, destination: SocketAddr) -> Result<()> {
        (self.filter)(destination)?;
        match self.guard {
            Some(guard) => guard.check_destination(destination),
            None => Ok(()),
        }
    }

    fn check_connected(&self, peer: SocketAddr, local: SocketAddr) -> Result<()> {
        match self.guard {
            Some(guard) => guard.check_connected(peer, local),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_enforcement_requires_an_allowed_distribution_point() {
        let mut settings = RevocationSettings {
            enforcement: RevocationEnforcement::HardFail,
            ..RevocationSettings::default()
        };
        assert!(settings.validate().is_err());
        settings.allowed_distribution_points =
            vec![DistributionPointPattern::parse("http://crl.example.com/**").unwrap()];
        settings.validate().unwrap();
        RevocationSettings::default().validate().unwrap();
    }

    #[test]
    fn prefetch_urls_must_match_an_allowed_pattern() {
        let mut settings = RevocationSettings {
            allowed_distribution_points: vec![DistributionPointPattern::parse(
                "http://**.pki.example.com/**/*.crl",
            )
            .unwrap()],
            prefetch_distribution_points: vec![DistributionPointUrl::parse(
                "http://primary.pki.example.com/a/current.crl",
            )
            .unwrap()],
            ..RevocationSettings::default()
        };
        settings.validate().unwrap();
        settings.prefetch_distribution_points =
            vec![DistributionPointUrl::parse("http://other.example.com/a/current.crl").unwrap()];
        assert!(settings.validate().is_err());
    }

    #[tokio::test]
    async fn network_filter_rejects_resolved_addresses_before_connecting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let network = RevocationNetwork::default();
        let error = network
            .connect("127.0.0.1", port, &|address| {
                ensure!(!address.ip().is_loopback(), "loopback is not allowed");
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("loopback is not allowed"));
        network
            .connect("127.0.0.1", port, &|_| Ok(()))
            .await
            .unwrap();
    }
}
