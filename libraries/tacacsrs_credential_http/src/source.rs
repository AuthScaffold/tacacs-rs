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

impl HttpCrlSource {
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
