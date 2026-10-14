//! Bounded HTTP retrieval behind the provider-neutral resolution contract.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use tokio::sync::Semaphore;

use tacacsrs_credential_resolution::{
    CertificateRevocationListsMaterial, CredentialKind, CredentialRequest, CredentialResolver,
    CredentialValidity, ProviderErrorKind, PublicBytes, ResolutionError, ResolvedCredential,
};

use crate::{CrlFetchLimits, HttpCrlSource};

/// Retrieves complete CRL sets from explicitly registered HTTP(S) sources.
///
/// Redirects, environment proxies, and idle connection pooling are disabled.
/// HTTPS uses normal platform certificate and hostname verification.
/// Dropping a resolution future cancels its owned request and releases capacity.
pub struct HttpCrlResolver {
    client: Client,
    sources: BTreeMap<String, Vec<Url>>,
    limits: CrlFetchLimits,
    capacity: Semaphore,
    fallback: Option<Arc<dyn CredentialResolver>>,
}

impl HttpCrlResolver {
    /// Creates a reusable provider client with fixed reference-to-location mappings.
    ///
    /// # Errors
    /// Rejects duplicate references or an unavailable HTTP client backend. Errors omit source details.
    pub fn new(
        sources: impl IntoIterator<Item = HttpCrlSource>,
        limits: CrlFetchLimits,
    ) -> anyhow::Result<Self> {
        let mut registered = BTreeMap::new();
        for source in sources {
            anyhow::ensure!(
                registered
                    .insert(source.reference, source.locations)
                    .is_none(),
                "Duplicate HTTP CRL reference"
            );
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .pool_max_idle_per_host(0)
            .timeout(limits.timeout)
            .build()
            .map_err(|_| anyhow::anyhow!("Could not initialize HTTP CRL retrieval"))?;
        Ok(Self {
            client,
            sources: registered,
            limits,
            capacity: Semaphore::new(limits.maximum_concurrent),
            fallback: None,
        })
    }

    /// Delegates unregistered references and other credential kinds to another provider.
    ///
    /// Failures for registered HTTP sources never fall back to another source.
    #[must_use]
    pub fn with_fallback(mut self, fallback: Arc<dyn CredentialResolver>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    async fn fetch(&self, locations: &[Url]) -> Result<Vec<PublicBytes>, ProviderErrorKind> {
        let mut total = 0usize;
        let mut lists = Vec::with_capacity(locations.len());
        for location in locations {
            let mut response = self
                .client
                .get(location.clone())
                .header(reqwest::header::ACCEPT, "application/pkix-crl")
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(|_| ProviderErrorKind::Unavailable)?;
            match response.status() {
                StatusCode::OK => {}
                StatusCode::NOT_FOUND => return Err(ProviderErrorKind::NotFound),
                StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => {
                    return Err(ProviderErrorKind::AccessDenied)
                }
                _ => return Err(ProviderErrorKind::Unavailable),
            }
            if response
                .headers()
                .get_all(reqwest::header::CONTENT_ENCODING)
                .iter()
                .any(|value| value.as_bytes() != b"identity")
            {
                return Err(ProviderErrorKind::InvalidMaterial);
            }
            let remaining = self.limits.maximum_bytes - total;
            if response
                .content_length()
                .is_some_and(|length| length > remaining as u64)
            {
                return Err(ProviderErrorKind::InvalidMaterial);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| ProviderErrorKind::Unavailable)?
            {
                if chunk.len() > self.limits.maximum_bytes - total {
                    return Err(ProviderErrorKind::InvalidMaterial);
                }
                total += chunk.len();
                bytes.extend_from_slice(&chunk);
            }
            if bytes.is_empty() {
                return Err(ProviderErrorKind::InvalidMaterial);
            }
            lists.push(PublicBytes::new(bytes));
        }
        Ok(lists)
    }
}

#[async_trait]
impl CredentialResolver for HttpCrlResolver {
    async fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> Result<ResolvedCredential, ResolutionError> {
        let source = (request.kind() == CredentialKind::CertificateRevocationLists)
            .then(|| request.reference().certificate_revocation_lists())
            .flatten()
            .and_then(|reference| self.sources.get(reference));
        let Some(locations) = source else {
            return match &self.fallback {
                Some(fallback) => fallback.resolve(request).await,
                None => {
                    Err(ResolutionError::provider(ProviderErrorKind::NotFound, request.context()))
                }
            };
        };
        let _permit = self.capacity.try_acquire().map_err(|_| {
            ResolutionError::provider(ProviderErrorKind::Unavailable, request.context())
        })?;
        let lists = tokio::time::timeout(self.limits.timeout, self.fetch(locations))
            .await
            .map_err(|_| {
                ResolutionError::provider(ProviderErrorKind::Unavailable, request.context())
            })?
            .map_err(|kind| ResolutionError::provider(kind, request.context()))?;
        Ok(ResolvedCredential::CertificateRevocationLists(CertificateRevocationListsMaterial {
            validity: CredentialValidity::unbounded(),
            lists,
        }))
    }
}

impl fmt::Debug for HttpCrlResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpCrlResolver")
            .field("source_count", &self.sources.len())
            .field("limits", &self.limits)
            .field("has_fallback", &self.fallback.is_some())
            .finish_non_exhaustive()
    }
}
