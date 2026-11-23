//! CRL distribution point URLs and the glob patterns that allow them.
//!
//! A pattern has the form `http://HOST[:PORT]/PATH`. The rules are strict
//! because a pattern decides which hosts the agent may contact:
//!
//! - The scheme must be `http`. CRLs are signed, and CRL distribution points
//!   normally use plain HTTP.
//! - In the host, the leftmost label can be `*`, which matches exactly one
//!   label, or `**`, which matches one or more labels. No other label can
//!   contain `*`. A wildcard host needs at least two literal labels after the
//!   wildcard, so `http://**.com/**` is invalid.
//! - In the path, a segment `**` matches zero or more whole segments. In other
//!   segments, `*` matches any characters inside one segment.
//! - Host names match without regard to case. Paths match exactly.
//! - Patterns and URLs cannot contain user information, a query, a fragment,
//!   a `.` or `..` segment, or an encoded `/`.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};

const HTTP_PORT: u16 = 80;

/// An exact CRL distribution point URL that is safe to fetch.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DistributionPointUrl {
    url: url::Url,
}

impl DistributionPointUrl {
    /// Parses an `http` URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is not `http`, has no host, or contains
    /// user information, a query, a fragment, a dot segment, an encoded `/`, or
    /// `*`.
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(!value.contains('*'), "CRL distribution point URL {value} contains '*'");
        let url = parse_http(value)?;
        Ok(Self { url })
    }

    /// Returns the host name or IP address literal.
    #[must_use]
    pub fn host(&self) -> &str {
        host_without_brackets(&self.url)
    }

    /// Returns the TCP port, which is 80 unless the URL names another port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.url.port().unwrap_or(HTTP_PORT)
    }

    /// Returns the percent-encoded path.
    #[must_use]
    pub fn path(&self) -> &str {
        self.url.path()
    }

    /// Returns the serialized URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }
}

impl FromStr for DistributionPointUrl {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl fmt::Display for DistributionPointUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for DistributionPointUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// A glob pattern for allowed CRL distribution point URLs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DistributionPointPattern {
    source: String,
    host: HostPattern,
    port: u16,
    path: Vec<PathSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum HostPattern {
    Exact(String),
    OneLabel(String),
    AnyLabels(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PathSegment {
    AnySegments,
    Glob(String),
}

impl DistributionPointPattern {
    /// Parses a pattern.
    ///
    /// # Errors
    ///
    /// Returns an error when the pattern breaks a rule in the module
    /// documentation.
    pub fn parse(value: &str) -> Result<Self> {
        let rest = value.strip_prefix("http://").with_context(|| {
            format!("Distribution point pattern {value} must start with http://")
        })?;
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let (authority, raw_path) = rest.split_at(authority_end);
        let (host, wildcard) = if let Some(suffix) = authority.strip_prefix("**.") {
            (suffix, Some(true))
        } else if let Some(suffix) = authority.strip_prefix("*.") {
            (suffix, Some(false))
        } else {
            (authority, None)
        };
        ensure!(
            !host.contains('*'),
            "Distribution point pattern {value} can use a wildcard only as the leftmost host label"
        );
        // Parse the literal part with the URL parser so that host
        // normalization and the other URL checks match DistributionPointUrl.
        let literal =
            parse_http(&format!("http://{host}{}", raw_path.replace("**", "x").replace('*', "x")))
                .with_context(|| format!("Invalid distribution point pattern {value}"))?;
        let literal_host = host_without_brackets(&literal).to_owned();
        let host = match wildcard {
            None => HostPattern::Exact(literal_host),
            Some(any) => {
                ensure!(
                    matches!(literal.host(), Some(url::Host::Domain(_))),
                    "Distribution point pattern {value} applies a wildcard to an IP address"
                );
                ensure!(
                    literal_host.split('.').filter(|label| !label.is_empty()).count() >= 2,
                    "Distribution point pattern {value} needs at least two literal host labels after the wildcard"
                );
                if any {
                    HostPattern::AnyLabels(literal_host)
                } else {
                    HostPattern::OneLabel(literal_host)
                }
            }
        };
        let path = parse_path(value, raw_path)?;
        Ok(Self {
            source: value.to_owned(),
            host,
            port: literal.port().unwrap_or(HTTP_PORT),
            path,
        })
    }

    /// Returns whether `url` matches this pattern.
    #[must_use]
    pub fn matches(&self, url: &DistributionPointUrl) -> bool {
        self.port == url.port() && self.host_matches(url.host()) && self.path_matches(url.path())
    }

    /// Returns the pattern text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    fn host_matches(&self, host: &str) -> bool {
        match &self.host {
            HostPattern::Exact(expected) => host == expected,
            HostPattern::OneLabel(suffix) => host
                .strip_suffix(suffix.as_str())
                .and_then(|prefix| prefix.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            HostPattern::AnyLabels(suffix) => host
                .strip_suffix(suffix.as_str())
                .and_then(|prefix| prefix.strip_suffix('.'))
                .is_some_and(|labels| labels.split('.').all(|label| !label.is_empty())),
        }
    }

    fn path_matches(&self, path: &str) -> bool {
        let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();
        match_segments(&self.path, &segments)
    }
}

impl FromStr for DistributionPointPattern {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl fmt::Display for DistributionPointPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.source)
    }
}

impl fmt::Debug for DistributionPointPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

fn parse_http(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value).with_context(|| format!("Invalid URL {value}"))?;
    ensure!(url.scheme() == "http", "URL {value} must use http");
    ensure!(url.host().is_some(), "URL {value} has no host");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URL {value} contains user information"
    );
    ensure!(url.query().is_none(), "URL {value} contains a query");
    ensure!(url.fragment().is_none(), "URL {value} contains a fragment");
    let raw_path = value
        .strip_prefix("http://")
        .and_then(|rest| rest.find('/').map(|index| &rest[index..]))
        .unwrap_or("/");
    for segment in raw_path.split('/') {
        let lower = segment.to_ascii_lowercase();
        if lower.contains("%2f") || lower.contains("%5c") || segment.contains('\\') {
            bail!("URL {value} contains an encoded path separator");
        }
        let decoded = lower.replace("%2e", ".");
        if decoded == "." || decoded == ".." {
            bail!("URL {value} contains a dot segment");
        }
    }
    Ok(url)
}

fn host_without_brackets(url: &url::Url) -> &str {
    let host = url.host_str().unwrap_or_default();
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

fn parse_path(source: &str, raw_path: &str) -> Result<Vec<PathSegment>> {
    let raw_path = raw_path.strip_prefix('/').unwrap_or(raw_path);
    let mut segments = Vec::new();
    for segment in raw_path.split('/') {
        if segment == "**" {
            if !matches!(segments.last(), Some(PathSegment::AnySegments)) {
                segments.push(PathSegment::AnySegments);
            }
        } else if segment.contains("**") {
            bail!("Distribution point pattern {source} uses '**' inside a path segment");
        } else {
            segments.push(PathSegment::Glob(segment.to_owned()));
        }
    }
    Ok(segments)
}

fn match_segments(pattern: &[PathSegment], segments: &[&str]) -> bool {
    let mut p = 0usize;
    let mut s = 0usize;
    let mut star: Option<(usize, usize)> = None;
    while s < segments.len() {
        if matches!(pattern.get(p), Some(PathSegment::AnySegments)) {
            star = Some((p, s + 1));
            p += 1;
        } else if matches!(
            pattern.get(p),
            Some(PathSegment::Glob(glob)) if glob_matches(glob, segments[s])
        ) {
            p += 1;
            s += 1;
        } else if let Some((star_p, next_s)) = star {
            p = star_p + 1;
            s = next_s;
            star = Some((star_p, next_s + 1));
        } else {
            return false;
        }
    }
    while matches!(pattern.get(p), Some(PathSegment::AnySegments)) {
        p += 1;
    }
    p == pattern.len()
}

fn glob_matches(glob: &str, value: &str) -> bool {
    let mut parts = glob.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut remaining) = value.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return remaining.is_empty();
    };
    for part in middle {
        match remaining.find(part) {
            Some(index) => remaining = &remaining[index + part.len()..],
            None => return false,
        }
    }
    remaining.len() >= last.len() && remaining.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> DistributionPointUrl {
        DistributionPointUrl::parse(value).unwrap()
    }

    #[test]
    fn azure_patterns_match_every_published_mirror() {
        let pki =
            DistributionPointPattern::parse("http://**.pki.core.windows.net/**/*.crl").unwrap();
        let microsoft =
            DistributionPointPattern::parse("http://crl.microsoft.com/**/*.crl").unwrap();
        for mirror in [
            "http://primary-cdn.pki.core.windows.net/eastus2/crls/ccmeeastus2pki/ccmeeastus2ica01/22/current.crl",
            "http://secondary-cdn.pki.core.windows.net/eastus2/crls/ccmeeastus2pki/ccmeeastus2ica01/22/current.crl",
            "http://ccmeeastus2pki.eastus2.pki.core.windows.net/certificateAuthorities/ccmeeastus2ica01/22/current.crl",
        ] {
            assert!(pki.matches(&url(mirror)), "{mirror}");
            assert!(!microsoft.matches(&url(mirror)), "{mirror}");
        }
        let fallback = url(
            "http://crl.microsoft.com/eastus2/crls/ccmeeastus2pki/ccmeeastus2ica01/22/current.crl",
        );
        assert!(microsoft.matches(&fallback));
        assert!(!pki.matches(&fallback));
    }

    #[test]
    fn host_wildcards_match_labels_from_the_right() {
        let one = DistributionPointPattern::parse("http://*.example.com/**").unwrap();
        let many = DistributionPointPattern::parse("http://**.example.com/**").unwrap();
        assert!(one.matches(&url("http://a.example.com/x.crl")));
        assert!(!one.matches(&url("http://a.b.example.com/x.crl")));
        assert!(many.matches(&url("http://a.b.EXAMPLE.com/x.crl")));
        for host in ["example.com", "evilexample.com", "a.example.com.evil.net"] {
            let candidate = url(&format!("http://{host}/x.crl"));
            assert!(!one.matches(&candidate), "{host}");
            assert!(!many.matches(&candidate), "{host}");
        }
    }

    #[test]
    fn ports_and_paths_must_match() {
        let pattern = DistributionPointPattern::parse("http://crl.example.com/ca/*.crl").unwrap();
        assert!(pattern.matches(&url("http://crl.example.com:80/ca/current.crl")));
        assert!(!pattern.matches(&url("http://crl.example.com:8080/ca/current.crl")));
        assert!(!pattern.matches(&url("http://crl.example.com/ca/sub/current.crl")));
        assert!(!pattern.matches(&url("http://crl.example.com/ca/current.crt")));
        assert!(!pattern.matches(&url("http://crl.example.com/CA/current.crl")));
        let any = DistributionPointPattern::parse("http://crl.example.com/**").unwrap();
        assert!(any.matches(&url("http://crl.example.com/")));
        assert!(any.matches(&url("http://crl.example.com/a/b/c.crl")));
        let ip = DistributionPointPattern::parse("http://[2001:db8::1]:8080/*.crl").unwrap();
        assert!(ip.matches(&url("http://[2001:db8::1]:8080/a.crl")));

        let multi = DistributionPointPattern::parse("http://crl.example.com/**/**/a/**/b/**/*.crl")
            .unwrap();
        let deep_miss = format!("http://crl.example.com/{}/x.txt", vec!["a"; 64].join("/"));
        assert!(!multi.matches(&url(&deep_miss)));
        let deep_hit = format!("http://crl.example.com/{}/b/c/leaf.crl", vec!["a"; 32].join("/"));
        assert!(multi.matches(&url(&deep_hit)));
    }

    #[test]
    fn unsafe_patterns_and_urls_are_rejected() {
        for pattern in [
            "https://crl.example.com/**",
            "http://**.com/**",
            "http://*.*.example.com/**",
            "http://crl.*.example.com/**",
            "http://*.10.0.0.1/**",
            "http://user@crl.example.com/**",
            "http://crl.example.com/a**/x.crl",
            "http://crl.example.com/../x.crl",
            "http://crl.example.com/%2e%2E/x.crl",
            "http://crl.example.com/a%2Fb/x.crl",
            "http://crl.example.com/x.crl?a=b",
            "http://crl.example.com/x.crl#a",
        ] {
            assert!(DistributionPointPattern::parse(pattern).is_err(), "{pattern}");
        }
        for value in [
            "http://crl.example.com/*.crl",
            "ldap://crl.example.com/x.crl",
            "http://user:pass@crl.example.com/x.crl",
            "http://crl.example.com/a/../x.crl",
            "http://crl.example.com/a%2fb.crl",
        ] {
            assert!(DistributionPointUrl::parse(value).is_err(), "{value}");
        }
    }
}
