//! Explicit retrieval locations and bounded provider execution policy.

use std::fmt;
use std::time::Duration;

use anyhow::ensure;
use reqwest::Url;

/// Bounds requests per evidence set independently of downloaded byte limits.
const MAXIMUM_LOCATIONS: usize = 16;

/// Host-authorized locations for one opaque CRL evidence reference.
#[derive(Clone)]
pub struct HttpCrlSource {
    pub(crate) reference: String,
    pub(crate) locations: Vec<Url>,
}

/// Host-authorized OCSP query for one certificate and its issuer.
#[derive(Clone)]
pub struct HttpOcspSource {
    pub(crate) reference: String,
    pub(crate) location: Url,
    pub(crate) request: Vec<u8>,
}

impl HttpOcspSource {
    /// Registers an explicit public responder URL and DER certificate pair.
    /// # Errors
    /// Rejects invalid URLs, malformed certificates, or an unrelated issuer.
    pub fn new(
        reference: impl Into<String>,
        location: &str,
        certificate: &[u8],
        issuer: &[u8],
    ) -> anyhow::Result<Self> {
        let source = HttpCrlSource::new(reference, [location])?;
        ensure!(
            certificate.len() <= 1024 * 1024 && issuer.len() <= 1024 * 1024,
            "OCSP certificate input exceeds the size limit"
        );
        let peer = openssl::x509::X509::from_der(certificate)?;
        let authority = openssl::x509::X509::from_der(issuer)?;
        ensure!(
            peer.to_der()? == certificate && authority.to_der()? == issuer,
            "OCSP certificates must contain one DER value"
        );
        ensure!(
            authority.issued(&peer) == openssl::x509::X509VerifyResult::OK
                && peer.verify(authority.public_key()?.as_ref())?,
            "OCSP issuer does not match the certificate"
        );
        let mut request = openssl::ocsp::OcspRequest::new()?;
        request.add_id(openssl::ocsp::OcspCertId::from_cert(
            openssl::hash::MessageDigest::sha256(),
            &peer,
            &authority,
        )?)?;
        Ok(Self {
            reference: source.reference,
            location: source.locations[0].clone(),
            request: request.to_der()?,
        })
    }

    /// Selects the first certificate AIA URL present in the host allowlist.
    /// # Errors
    /// Rejects malformed input or the absence of an authorized responder.
    pub fn from_certificate(
        reference: impl Into<String>,
        certificate: &[u8],
        issuer: &[u8],
        allowed_locations: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> anyhow::Result<Self> {
        let allowed = HttpCrlSource::new(reference, allowed_locations)?;
        ensure!(certificate.len() <= 1024 * 1024, "OCSP certificate input exceeds the size limit");
        let peer = openssl::x509::X509::from_der(certificate)?;
        for location in peer.ocsp_responders()? {
            if let Ok(location) = Url::parse(&location) {
                if allowed.locations.contains(&location) {
                    return Self::new(allowed.reference, location.as_str(), certificate, issuer);
                }
            }
        }
        anyhow::bail!("Certificate has no authorized OCSP responder")
    }
}

impl fmt::Debug for HttpOcspSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpOcspSource")
            .field("reference", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl HttpCrlSource {
    /// Discovers CRL URLs from host-supplied DER certificates under an exact URL allowlist.
    ///
    /// # Errors
    /// Rejects malformed certificates, unsupported distribution points, unapproved URLs,
    /// empty results, or more than sixteen certificates or locations. Errors omit source values.
    pub fn from_certificates(
        reference: impl Into<String>,
        certificates: &[&[u8]],
        allowed_locations: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> anyhow::Result<Self> {
        let allowed = Self::new(reference, allowed_locations)?;
        ensure!(
            !certificates.is_empty() && certificates.len() <= MAXIMUM_LOCATIONS,
            "CRL discovery requires one to sixteen certificates"
        );
        ensure!(
            certificates
                .iter()
                .try_fold(0usize, |total, certificate| total.checked_add(certificate.len()))
                .is_some_and(|total| total <= 4 * 1024 * 1024),
            "CRL discovery certificate set exceeds the size limit"
        );
        let mut locations = Vec::new();
        for encoded in certificates {
            let certificate = openssl::x509::X509::from_der(encoded)
                .map_err(|_| anyhow::anyhow!("Invalid CRL discovery certificate"))?;
            ensure!(
                certificate.to_der()?.as_slice() == *encoded,
                "Discovery certificate must contain one DER value"
            );
            if let Some(points) = certificate.crl_distribution_points() {
                for point in points {
                    let names = point
                        .distpoint()
                        .and_then(openssl::x509::DistPointNameRef::fullname)
                        .ok_or_else(|| {
                            anyhow::anyhow!("CRL discovery requires full URI distribution points")
                        })?;
                    let mut found = false;
                    for name in names {
                        let Some(location) = name.uri() else {
                            continue;
                        };
                        found = true;
                        let parsed = Self::new("discovery", [location])?;
                        let location = &parsed.locations[0];
                        ensure!(
                            allowed.locations.contains(location),
                            "Certificate CRL location is not authorized"
                        );
                        if !locations.contains(location) {
                            ensure!(
                                locations.len() < MAXIMUM_LOCATIONS,
                                "CRL discovery has too many locations"
                            );
                            locations.push(location.clone());
                        }
                    }
                    ensure!(found, "CRL distribution point has no URI");
                }
            }
        }
        ensure!(!locations.is_empty(), "Certificates contain no usable CRL locations");
        Ok(Self {
            reference: allowed.reference,
            locations,
        })
    }

    /// Registers HTTP(S) locations in deterministic fetch order.
    ///
    /// # Errors
    /// Rejects empty references, empty or oversized sets, non-HTTP URLs, credentials, queries, and fragments.
    /// Errors omit reference and URL values.
    pub fn new(
        reference: impl Into<String>,
        locations: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> anyhow::Result<Self> {
        let reference = reference.into();
        ensure!(!reference.is_empty(), "HTTP CRL reference must not be empty");
        let mut parsed = Vec::new();
        for location in locations {
            ensure!(parsed.len() < MAXIMUM_LOCATIONS, "HTTP CRL set has too many locations");
            let url = Url::parse(location.as_ref())
                .map_err(|_| anyhow::anyhow!("Invalid HTTP CRL location"))?;
            ensure!(
                matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
                "CRL locations must use HTTP or HTTPS"
            );
            ensure!(
                url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "CRL locations cannot contain credentials, queries, or fragments"
            );
            ensure!(!parsed.contains(&url), "HTTP CRL locations must be unique");
            parsed.push(url);
        }
        ensure!(!parsed.is_empty(), "HTTP CRL set has no locations");
        Ok(Self {
            reference,
            locations: parsed,
        })
    }
}

impl fmt::Debug for HttpCrlSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpCrlSource")
            .field("reference", &"<redacted>")
            .field("location_count", &self.locations.len())
            .finish_non_exhaustive()
    }
}

/// Resource limits for one provider and each complete CRL-set fetch.
#[derive(Debug, Clone, Copy)]
pub struct CrlFetchLimits {
    pub(crate) timeout: Duration,
    pub(crate) maximum_bytes: usize,
    pub(crate) maximum_concurrent: usize,
}

impl CrlFetchLimits {
    /// Sets a total fetch timeout, aggregate byte cap, and active-fetch cap.
    ///
    /// # Errors
    /// Rejects zero limits, byte caps above 4 MiB, concurrency above the runtime limit,
    /// or timeouts above `u32::MAX` seconds.
    pub fn new(
        timeout: Duration,
        maximum_bytes: usize,
        maximum_concurrent: usize,
    ) -> anyhow::Result<Self> {
        ensure!(
            !timeout.is_zero() && maximum_bytes > 0 && maximum_concurrent > 0,
            "HTTP CRL limits must be positive"
        );
        ensure!(
            maximum_bytes <= 4 * 1024 * 1024,
            "HTTP CRL byte cap exceeds the native evidence limit"
        );
        ensure!(
            maximum_concurrent <= tokio::sync::Semaphore::MAX_PERMITS,
            "HTTP CRL concurrency exceeds the runtime limit"
        );
        ensure!(
            timeout <= Duration::from_secs(u64::from(u32::MAX)),
            "HTTP CRL timeout exceeds the supported range"
        );
        Ok(Self {
            timeout,
            maximum_bytes,
            maximum_concurrent,
        })
    }
}

impl Default for CrlFetchLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            maximum_bytes: 4 * 1024 * 1024,
            maximum_concurrent: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_policy_is_explicit_and_redacted() {
        let source =
            HttpCrlSource::new("private-reference", ["https://example.test/ca.crl"]).unwrap();
        let debug = format!("{source:?}");
        for value in ["private-reference", "example.test", "private-query"] {
            assert!(!debug.contains(value));
        }
        for location in [
            "file:///etc/secret",
            "ftp://example.test/crl",
            "https://user:password@example.test/crl",
            "https://example.test/crl?token=private-query",
            "https://example.test/crl#fragment",
            "not-a-url",
        ] {
            let error = HttpCrlSource::new("private-reference", [location]).unwrap_err();
            assert!(!format!("{error:#}").contains(location));
        }
        assert!(HttpCrlSource::new("empty", Vec::<String>::new()).is_err());
        assert!(HttpCrlSource::new(
            "duplicate",
            ["http://example.test/crl", "http://example.test/crl"]
        )
        .is_err());
        assert!(CrlFetchLimits::new(Duration::ZERO, 1, 1).is_err());
        assert!(CrlFetchLimits::new(Duration::MAX, 1, 1).is_err());
        assert!(CrlFetchLimits::new(Duration::from_secs(1), 1, usize::MAX).is_err());
        assert!(CrlFetchLimits::new(Duration::from_secs(1), 0, 1).is_err());
        assert!(CrlFetchLimits::new(Duration::from_secs(1), 4 * 1024 * 1024 + 1, 1).is_err());
        assert!(CrlFetchLimits::new(Duration::from_secs(1), 1, 0).is_err());
        assert!(HttpCrlSource::new("", ["http://example.test/crl"]).is_err());
        assert!(HttpCrlSource::new(
            "too-many",
            (0..17).map(|index| format!("http://example.test/{index}"))
        )
        .is_err());
    }
}
