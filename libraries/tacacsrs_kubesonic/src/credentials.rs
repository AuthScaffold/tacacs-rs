//! Mounted identity and CA material for explicitly authorized profile references.

use std::collections::BTreeSet;
use std::fs::{Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{ensure, Context};
use async_trait::async_trait;
use futures_util::{stream, StreamExt};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use tokio::sync::watch;
use zeroize::Zeroizing;

use tacacsrs_config::input::{normalize_cli_certificate_data, normalize_cli_private_key_data};
use tacacsrs_credential_resolution::{
    CertificateBagMaterial, CertificateWithKeyMaterial, CredentialChangeError,
    CredentialChangeEvent, CredentialChangeScope, CredentialChangeSource, CredentialChangeStream,
    CredentialKind, CredentialRequest, CredentialResolver, CredentialValidity,
    NamedCertificateMaterial, PrivateKeyFormat, ProviderErrorKind, PublicBytes, ResolutionError,
    ResolvedCredential, WorkScope,
};
use tacacsrs_secrets::SecretBytes;

use crate::environment::CredentialSettings;

pub(crate) const IDENTITY_REFERENCE: &str = "kubesonic-client-identity";
pub(crate) const CA_REFERENCE: &str = "kubesonic-server-ca";

/// Provider for the mounted KubeSONiC identity and trust.
#[derive(Clone)]
pub struct MountedCredentials {
    settings: CredentialSettings,
}

impl MountedCredentials {
    /// Authorizes only the paths in this startup configuration.
    #[must_use]
    pub fn new(settings: CredentialSettings) -> Self {
        Self { settings }
    }

    fn identity(&self) -> anyhow::Result<ResolvedCredential> {
        let certificate = read_file(&self.settings.certificate, self.settings.max_identity_bytes)?;
        let key = if self.settings.key == self.settings.certificate {
            None
        } else {
            Some(read_file(&self.settings.key, self.settings.max_identity_bytes)?)
        };
        let chain = normalize_cli_certificate_data(certificate.expose_secret())?;
        let (key_bytes, format) =
            normalize_cli_private_key_data(key.as_ref().unwrap_or(&certificate).expose_secret())?;
        let private_key_format = match format {
            tacacsrs_config::crypto_types::PrivateKeyFormat::RsaPrivateKeyFormat => {
                PrivateKeyFormat::RsaPrivateKeyFormat
            }
            tacacsrs_config::crypto_types::PrivateKeyFormat::EcPrivateKeyFormat => {
                PrivateKeyFormat::EcPrivateKeyFormat
            }
            tacacsrs_config::crypto_types::PrivateKeyFormat::OneAsymmetricKeyFormat => {
                PrivateKeyFormat::OneAsymmetricKeyFormat
            }
        };
        Ok(ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
            validity: CredentialValidity::unbounded(),
            public_key_format: None,
            public_key: None,
            private_key_format,
            certificate: PublicBytes::new(chain.leaf),
            intermediates: chain
                .intermediates
                .into_iter()
                .map(PublicBytes::new)
                .collect(),
            private_key: SecretBytes::new(key_bytes),
        }))
    }

    fn authorities(&self, scope: &WorkScope) -> anyhow::Result<ResolvedCredential> {
        let bundle_before = std::fs::metadata(&self.settings.ca_file)?;
        let directory_before = std::fs::metadata(&self.settings.ca_directory)?;
        let mut certificates = BTreeSet::new();
        self.add_certificates(&self.settings.ca_file, &mut certificates)?;
        let mut entries = 0usize;
        for entry in std::fs::read_dir(&self.settings.ca_directory)
            .context("Read mounted trust directory")?
        {
            ensure!(scope.register().is_some(), "Credential resolution was cancelled");
            let entry = entry.context("Read mounted trust entry")?;
            entries += 1;
            ensure!(
                entries <= self.settings.max_directory_entries,
                "Mounted trust directory exceeds its entry limit"
            );
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if hashed_certificate_name(name) {
                self.add_certificates(&entry.path(), &mut certificates)?;
            }
        }
        ensure!(!certificates.is_empty(), "Mounted trust has no certificates");
        ensure!(
            same_file(&bundle_before, &std::fs::metadata(&self.settings.ca_file)?)
                && same_file(&directory_before, &std::fs::metadata(&self.settings.ca_directory)?),
            "Mounted trust changed during its read"
        );
        Ok(ResolvedCredential::CaCertificateBag(CertificateBagMaterial {
            validity: CredentialValidity::unbounded(),
            certificates: certificates
                .into_iter()
                .enumerate()
                .map(|(index, bytes)| NamedCertificateMaterial {
                    name: format!("ca-{index}"),
                    certificate: PublicBytes::new(bytes),
                })
                .collect(),
        }))
    }

    fn add_certificates(
        &self,
        path: &Path,
        certificates: &mut BTreeSet<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let bytes = read_file(path, self.settings.max_ca_file_bytes)?;
        let mut found = false;
        for certificate in CertificateDer::pem_slice_iter(bytes.expose_secret()) {
            let certificate = certificate
                .map_err(|_| anyhow::anyhow!("Mounted CA certificates are not valid PEM"))?;
            found = true;
            certificates.insert(certificate.as_ref().to_vec());
            ensure!(
                certificates.len() <= self.settings.max_certificates,
                "Mounted trust exceeds its certificate limit"
            );
            let total = certificates
                .iter()
                .try_fold(0u64, |total, certificate| {
                    total.checked_add(u64::try_from(certificate.len()).ok()?)
                })
                .context("Mounted trust size overflow")?;
            ensure!(
                total <= self.settings.max_trust_bytes,
                "Mounted trust exceeds its total byte limit"
            );
        }
        ensure!(found, "Mounted CA file has no PEM certificates");
        Ok(())
    }
}

fn hashed_certificate_name(name: &str) -> bool {
    let Some((hash, suffix)) = name.split_once('.') else {
        return false;
    };
    hash.len() == 8
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn read_file(path: &Path, limit: u64) -> anyhow::Result<SecretBytes> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .context("Open mounted credential")?;
    let before = file
        .metadata()
        .context("Read mounted credential metadata")?;
    ensure!(
        before.is_file() && before.len() <= limit,
        "Mounted credential type or size is invalid"
    );
    let mut data = Zeroizing::new(Vec::new());
    file.take(
        limit
            .checked_add(1)
            .context("Credential read limit overflow")?,
    )
    .read_to_end(&mut data)
    .context("Read mounted credential")?;
    let bytes = SecretBytes::from_zeroizing(data);
    ensure!(
        u64::try_from(bytes.expose_secret().len())? <= limit,
        "Mounted credential exceeds its read limit"
    );
    let after = std::fs::metadata(path).context("Read current credential metadata")?;
    ensure!(same_file(&before, &after), "Mounted credential changed during its read");
    Ok(bytes)
}

#[async_trait]
impl CredentialResolver for MountedCredentials {
    async fn resolve(
        &self,
        request: &CredentialRequest,
        scope: &WorkScope,
    ) -> Result<ResolvedCredential, ResolutionError> {
        let fail = |kind| ResolutionError::provider(kind, request.context());
        let identity = request.kind() == CredentialKind::CertificateWithKey
            && request.reference().certificate_with_key()
                == Some((Some(IDENTITY_REFERENCE), Some(IDENTITY_REFERENCE)));
        let authorities = request.kind() == CredentialKind::CaCertificateBag
            && request.reference().certificate_bag() == Some(CA_REFERENCE);
        if !identity && !authorities {
            return Err(fail(ProviderErrorKind::AccessDenied));
        }
        let lease = scope
            .register()
            .ok_or_else(|| fail(ProviderErrorKind::Unavailable))?;
        let provider = self.clone();
        let (result, _lease) = tokio::task::spawn_blocking(move || {
            let result = if identity {
                provider.identity()
            } else {
                provider.authorities(&lease)
            };
            (result, lease)
        })
        .await
        .map_err(|_| fail(ProviderErrorKind::Unavailable))?;
        result.map_err(|_| fail(ProviderErrorKind::InvalidMaterial))
    }
}

#[async_trait]
impl CredentialChangeSource for MountedCredentials {
    async fn subscribe(&self) -> Result<CredentialChangeStream, CredentialChangeError> {
        let (sender, receiver) = watch::channel(false);
        let files = [
            self.settings.certificate.clone(),
            self.settings.key.clone(),
            self.settings.ca_file.clone(),
        ];
        let trust_directory = self.settings.ca_directory.clone();
        let mut watcher = RecommendedWatcher::new(
            move |event: Result<notify::Event, notify::Error>| {
                if event
                    .as_ref()
                    .is_ok_and(|event| matches!(event.kind, notify::EventKind::Access(_)))
                {
                    return;
                }
                if event.as_ref().is_ok_and(|event| {
                    !event.paths.is_empty()
                        && !event.paths.iter().any(|path| {
                            files.iter().any(|file| {
                                file == path
                                    || file.canonicalize().is_ok_and(|target| target == *path)
                            }) || *path == trust_directory
                                || (path.parent() == Some(trust_directory.as_path())
                                    && path
                                        .file_name()
                                        .and_then(|name| name.to_str())
                                        .is_some_and(hashed_certificate_name))
                        })
                }) {
                    return;
                }
                if event.is_err() {
                    log::warn!("Mounted credential notifications are unavailable");
                }
                sender.send_replace(event.is_err());
            },
            Config::default(),
        )
        .map_err(|_| CredentialChangeError)?;
        let mut directories = BTreeSet::from([self.settings.ca_directory.clone()]);
        for path in [
            &self.settings.certificate,
            &self.settings.key,
            &self.settings.ca_file,
        ] {
            directories.insert(path.parent().ok_or(CredentialChangeError)?.to_path_buf());
        }
        for directory in directories {
            watcher
                .watch(&directory, RecursiveMode::NonRecursive)
                .map_err(|_| CredentialChangeError)?;
        }
        let debounce = self.settings.debounce;
        let interval = self.settings.reconcile_interval;
        let changes =
            stream::unfold((watcher, receiver), move |(watcher, mut receiver)| async move {
                match tokio::time::timeout(interval, receiver.changed()).await {
                    Ok(Err(_)) => return None,
                    Ok(Ok(())) => tokio::time::sleep(debounce).await,
                    Err(_) => {}
                }
                let failed = *receiver.borrow_and_update();
                let event = if failed {
                    CredentialChangeEvent::Unavailable
                } else {
                    CredentialChangeEvent::Changed(CredentialChangeScope::Unknown)
                };
                Some((event, (watcher, receiver)))
            });
        Ok(Box::pin(tokio_stream::once(CredentialChangeEvent::Recovered).chain(changes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_directory_matches_openssl_certificate_hash_names() {
        assert!(hashed_certificate_name("12abcdef.0"));
        assert!(!hashed_certificate_name("12abcdef.r0"));
        assert!(!hashed_certificate_name("unhashed.pem"));
    }

    #[test]
    fn bounded_reads_reject_oversize_and_directories() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input");
        std::fs::write(&path, "12345").unwrap();
        assert!(read_file(&path, 4).is_err());
        assert_eq!(read_file(&path, 5).unwrap().expose_secret(), b"12345");
        assert!(read_file(directory.path(), 5).is_err());
    }
}
