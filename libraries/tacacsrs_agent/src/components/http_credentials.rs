//! Adds HTTP certificate revocation evidence to credential resolution.
//!
//! The host authorizes each URL. The resolver never uses a URL that the host
//! did not register.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dill::component;
use tokio::io::AsyncReadExt;

use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_credential_http::{
    EvidenceFetchLimits, HttpEvidenceResolver, HttpCrlSource, HttpOcspSource,
};
use tacacsrs_credential_resolution::CredentialResolver;
use tacacsrs_provider::CredentialLayer;

/// The maximum size of a registered certificate file, 1 MiB.
const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;

/// One credential reference that the resolver answers from CRL URLs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpCrlRegistration {
    /// The credential reference.
    pub reference: String,
    /// The authorized CRL URLs.
    pub urls: Vec<String>,
    /// DER certificate files. The resolver uses only the CRL distribution
    /// points of these certificates that are also in `urls`.
    pub discovery_certificates: Vec<PathBuf>,
}

/// One credential reference that the resolver answers from an OCSP responder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpOcspRegistration {
    /// The credential reference.
    pub reference: String,
    /// The responder URL. If this value is `None`, the resolver discovers the
    /// responder from the certificate. The discovered URL must be in
    /// [`HttpEvidenceSettings::ocsp_allowed_urls`].
    pub responder: Option<String>,
    /// The DER certificate file to query.
    pub certificate: PathBuf,
    /// The DER issuer certificate file.
    pub issuer: PathBuf,
}

/// The HTTP evidence sources that a host authorizes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpEvidenceSettings {
    /// The CRL registrations. Each reference must be unique.
    pub crl_sources: Vec<HttpCrlRegistration>,
    /// The OCSP registrations.
    pub ocsp_sources: Vec<HttpOcspRegistration>,
    /// The exact URLs that OCSP discovery can use.
    pub ocsp_allowed_urls: Vec<String>,
}

impl HttpEvidenceSettings {
    /// Returns `true` when the settings register no source.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.crl_sources.is_empty() && self.ocsp_sources.is_empty()
    }

    /// Reads the certificate files and builds the resolver.
    ///
    /// Returns `None` when the settings register no source.
    ///
    /// # Errors
    /// Returns an error for an unreadable or invalid certificate file, an
    /// invalid URL, or a duplicate reference. The error does not contain the
    /// URL, the reference, or the file path.
    pub async fn resolver(&self) -> anyhow::Result<Option<HttpEvidenceResolver>> {
        if self.is_empty() {
            return Ok(None);
        }
        let mut crl = Vec::with_capacity(self.crl_sources.len());
        for registration in &self.crl_sources {
            let urls = registration.urls.iter().map(String::as_str);
            crl.push(if registration.discovery_certificates.is_empty() {
                HttpCrlSource::new(&registration.reference, urls)?
            } else {
                let mut certificates = Vec::new();
                for path in &registration.discovery_certificates {
                    certificates.push(read_certificate(path).await?);
                }
                HttpCrlSource::from_certificates(
                    &registration.reference,
                    &certificates.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    urls,
                )?
            });
        }
        let mut ocsp = Vec::with_capacity(self.ocsp_sources.len());
        for registration in &self.ocsp_sources {
            let certificate = read_certificate(&registration.certificate).await?;
            let issuer = read_certificate(&registration.issuer).await?;
            ocsp.push(match &registration.responder {
                Some(url) => {
                    HttpOcspSource::new(&registration.reference, url, &certificate, &issuer)?
                }
                None => HttpOcspSource::from_certificate(
                    &registration.reference,
                    &certificate,
                    &issuer,
                    &self.ocsp_allowed_urls,
                )?,
            });
        }
        Ok(Some(
            HttpEvidenceResolver::new(crl, EvidenceFetchLimits::default())?
                .with_ocsp_sources(ocsp)?,
        ))
    }
}

async fn read_certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| anyhow::anyhow!("Could not open registered discovery certificate"))?;
    let mut data = Vec::new();
    file.take(MAX_CERTIFICATE_BYTES + 1)
        .read_to_end(&mut data)
        .await
        .map_err(|_| anyhow::anyhow!("Could not read registered discovery certificate"))?;
    anyhow::ensure!(
        !data.is_empty() && data.len() as u64 <= MAX_CERTIFICATE_BYTES,
        "Discovery certificate size is invalid"
    );
    Ok(data)
}

/// Adds the HTTP evidence resolver in front of the source resolver.
///
/// The component reads the certificate files in `prepare`. When the settings
/// register no source, the component registers nothing.
pub struct HttpCredentialComponent {
    settings: HttpEvidenceSettings,
    resolver: Option<HttpEvidenceResolver>,
}

impl HttpCredentialComponent {
    /// Creates the component with the authorized sources.
    #[must_use]
    pub const fn new(settings: HttpEvidenceSettings) -> Self {
        Self {
            settings,
            resolver: None,
        }
    }
}

#[async_trait::async_trait]
impl Component for HttpCredentialComponent {
    fn name(&self) -> &'static str {
        HttpCredentialLayer::NAME
    }

    async fn prepare(&mut self) -> anyhow::Result<()> {
        self.resolver = self.settings.resolver().await?;
        Ok(())
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let Some(resolver) = self.resolver else {
            return Ok(());
        };
        composition.member::<dyn CredentialLayer, HttpCredentialLayer, _>(
            HttpCredentialLayer::builder(Arc::new(Mutex::new(Some(resolver)))),
        )
    }
}

/// Puts the HTTP evidence resolver in front of the source resolver.
///
/// The HTTP resolver answers the references that it registers. It sends other
/// requests to the source resolver.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn CredentialLayer)]
struct HttpCredentialLayer {
    #[component(explicit)]
    resolver: Arc<Mutex<Option<HttpEvidenceResolver>>>,
}

impl Named for HttpCredentialLayer {
    const NAME: &'static str = "HTTP credential evidence";
}

impl CredentialLayer for HttpCredentialLayer {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn wrap(
        &self,
        inner: Option<Arc<dyn CredentialResolver>>,
    ) -> anyhow::Result<Arc<dyn CredentialResolver>> {
        let resolver = self
            .resolver
            .lock()
            .map_err(|_| anyhow::anyhow!("The HTTP credential layer lock is poisoned"))?
            .take()
            .ok_or_else(|| anyhow::anyhow!("The HTTP credential layer is already applied"))?;
        Ok(Arc::new(match inner {
            Some(fallback) => resolver.with_fallback(fallback),
            None => resolver,
        }))
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_credential_resolution::FakeCredentialResolver;

    use super::*;

    fn crl(reference: &str, urls: &[&str]) -> HttpEvidenceSettings {
        HttpEvidenceSettings {
            crl_sources: vec![HttpCrlRegistration {
                reference: reference.to_owned(),
                urls: urls.iter().map(|url| (*url).to_owned()).collect(),
                discovery_certificates: Vec::new(),
            }],
            ..HttpEvidenceSettings::default()
        }
    }

    #[tokio::test]
    async fn crl_registration_accepts_locations_and_rejects_invalid_sources() {
        let settings = crl(
            "opaque",
            &[
                "https://example.test/root.crl",
                "https://example.test/issuer.crl",
            ],
        );
        assert!(settings.resolver().await.unwrap().is_some());
        let duplicate = crl(
            "opaque",
            &[
                "https://example.test/root.crl",
                "https://example.test/root.crl",
            ],
        );
        assert!(duplicate.resolver().await.is_err());
        for url in [
            "file:///etc/private",
            "http://user:secret@example.test/crl",
            "http://example.test/crl?secret=value",
        ] {
            let error = crl("private-reference", &[url])
                .resolver()
                .await
                .err()
                .unwrap();
            assert!(!format!("{error:#}").contains(url));
            assert!(!format!("{error:#}").contains("private-reference"));
        }
    }

    #[tokio::test]
    async fn missing_certificate_files_fail_without_the_path() {
        let settings = HttpEvidenceSettings {
            ocsp_sources: vec![HttpOcspRegistration {
                reference: "opaque".to_owned(),
                responder: Some("https://example.test/ocsp".to_owned()),
                certificate: PathBuf::from("/nonexistent/private-certificate.der"),
                issuer: PathBuf::from("/nonexistent/issuer.der"),
            }],
            ..HttpEvidenceSettings::default()
        };
        let error = settings.resolver().await.err().unwrap();
        assert!(!format!("{error:#}").contains("private-certificate"));
    }

    #[tokio::test]
    async fn layer_is_optional_and_wraps_the_source_resolver_once() {
        assert!(HttpEvidenceSettings::default()
            .resolver()
            .await
            .unwrap()
            .is_none());
        let layer = HttpCredentialLayer {
            resolver: Arc::new(Mutex::new(
                crl("opaque", &["https://example.test/crl"])
                    .resolver()
                    .await
                    .unwrap(),
            )),
        };
        let source: Arc<dyn CredentialResolver> = Arc::new(FakeCredentialResolver::new());
        assert!(layer.wrap(Some(source)).is_ok());
        assert!(layer.wrap(None).is_err());
    }
}
