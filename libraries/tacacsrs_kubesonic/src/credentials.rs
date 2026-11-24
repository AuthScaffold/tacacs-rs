//! Mounted identity and CA material for explicitly authorized profile references.

use std::collections::BTreeSet;
use std::fs::{Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context};
use async_trait::async_trait;
use futures_util::{stream, StreamExt};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use tokio::sync::watch;
use x509_cert::{der::Decode, Certificate};
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
        let validity = chain_validity(&chain.leaf, &chain.intermediates)?;
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
            validity,
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
        let bundle_before =
            optional_metadata(&self.settings.ca_file, self.settings.ca_file_required)
                .context("Read mounted CA bundle metadata")?;
        let directory_before =
            optional_metadata(&self.settings.ca_directory, self.settings.ca_directory_required)
                .context("Read mounted trust directory metadata")?;
        let mut certificates = BTreeSet::new();
        if bundle_before.is_some() {
            self.add_certificates(&self.settings.ca_file, &mut certificates)?;
        }
        if directory_before.is_some() {
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
        }
        ensure!(!certificates.is_empty(), "Mounted trust has no certificates");
        if let Some(before) = &bundle_before {
            ensure!(
                same_file(before, &std::fs::metadata(&self.settings.ca_file)?),
                "Mounted trust changed during its read"
            );
        }
        if let Some(before) = &directory_before {
            ensure!(
                same_file(before, &std::fs::metadata(&self.settings.ca_directory)?),
                "Mounted trust changed during its read"
            );
        }
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

fn certificate_validity(der: &[u8]) -> anyhow::Result<CredentialValidity> {
    let certificate = Certificate::from_der(der).context("Decode mounted client certificate")?;
    let validity = certificate.tbs_certificate().validity();
    CredentialValidity::new(
        Some(validity.not_before.to_system_time()),
        Some(validity.not_after.to_system_time()),
    )
    .context("Mounted client certificate validity interval is empty")
}

fn chain_validity(leaf: &[u8], intermediates: &[Vec<u8>]) -> anyhow::Result<CredentialValidity> {
    let mut validity = certificate_validity(leaf)?;
    for intermediate in intermediates {
        validity = validity
            .intersect(certificate_validity(intermediate)?)
            .context("Mounted client certificate chain has no overlapping validity")?;
    }
    Ok(validity)
}

fn optional_metadata(path: &Path, required: bool) -> std::io::Result<Option<Metadata>> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => Ok(None),
        Err(error) => Err(error),
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
        let projection_directories: Vec<PathBuf> = files
            .iter()
            .filter_map(|file| file.parent().map(Path::to_path_buf))
            .chain(std::iter::once(trust_directory.clone()))
            .collect();
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
                            }) || kubelet_projection_entry(path, &projection_directories)
                                || *path == trust_directory
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
        let mut directories = BTreeSet::new();
        for path in [&self.settings.certificate, &self.settings.key] {
            directories.insert(path.parent().ok_or(CredentialChangeError)?.to_path_buf());
        }
        let ca_parent = self
            .settings
            .ca_file
            .parent()
            .ok_or(CredentialChangeError)?;
        if self.settings.ca_file_required || ca_parent.exists() {
            directories.insert(ca_parent.to_path_buf());
        }
        if self.settings.ca_directory_required || self.settings.ca_directory.exists() {
            directories.insert(self.settings.ca_directory.clone());
        } else if let Some(parent) = self
            .settings
            .ca_directory
            .parent()
            .filter(|parent| parent.exists())
        {
            directories.insert(parent.to_path_buf());
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

/// Returns whether a path is a kubelet projection entry inside a watched directory.
///
/// The kubelet publishes a Secret or ConfigMap volume update as one rename of
/// `..data_tmp` to `..data`. The visible file names are symbolic links through
/// `..data`, so the update produces no event for the visible names.
fn kubelet_projection_entry(path: &Path, directories: &[PathBuf]) -> bool {
    path.parent()
        .is_some_and(|parent| directories.iter().any(|directory| directory == parent))
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn watches_each_identity_and_ca_file_for_writes_and_replacements() {
        for selected in 0..3 {
            for replace in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let root = directory.path();
                let mut files = Vec::new();
                for name in ["certificate", "key", "ca"] {
                    let parent = root.join(name);
                    std::fs::create_dir(&parent).unwrap();
                    let path = parent.join("current.pem");
                    std::fs::write(&path, "original").unwrap();
                    files.push(path);
                }
                let trust = root.join("trust");
                std::fs::create_dir(&trust).unwrap();
                let mut settings = crate::environment::Environment::parse(Default::default())
                    .unwrap()
                    .credentials;
                settings.certificate = files[0].clone();
                settings.key = files[1].clone();
                settings.ca_file = files[2].clone();
                settings.ca_directory = trust;
                settings.debounce = std::time::Duration::from_millis(10);
                settings.reconcile_interval = std::time::Duration::from_secs(60);
                let mut stream = MountedCredentials::new(settings).subscribe().await.unwrap();
                assert!(matches!(stream.next().await, Some(CredentialChangeEvent::Recovered)));
                if replace {
                    let next = root.join("replacement.pem");
                    std::fs::write(&next, "replacement").unwrap();
                    std::fs::rename(next, &files[selected]).unwrap();
                } else {
                    std::fs::write(&files[selected], "updated").unwrap();
                }
                assert!(
                    matches!(
                        tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                            .await
                            .unwrap(),
                        Some(CredentialChangeEvent::Changed(_))
                    ),
                    "No notification for file {selected} (replacement: {replace})"
                );
            }
        }
    }

    #[tokio::test]
    async fn notifications_follow_rotated_targets_without_periodic_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let first = root.join("first.pem");
        let second = root.join("second.pem");
        let current = root.join("current.pem");
        let ca_file = root.join("ca.pem");
        let trust = root.join("trust");
        std::fs::create_dir(&trust).unwrap();
        std::fs::write(&first, "first").unwrap();
        std::fs::write(&second, "second").unwrap();
        std::fs::write(&ca_file, "ca").unwrap();
        std::os::unix::fs::symlink(&first, &current).unwrap();
        let mut settings = crate::environment::Environment::parse(Default::default())
            .unwrap()
            .credentials;
        settings.certificate = current.clone();
        settings.key = current.clone();
        settings.ca_file = ca_file;
        settings.ca_directory = trust.clone();
        settings.debounce = std::time::Duration::from_millis(10);
        settings.reconcile_interval = std::time::Duration::from_secs(60);
        let mut stream = MountedCredentials::new(settings).subscribe().await.unwrap();
        assert!(matches!(stream.next().await, Some(CredentialChangeEvent::Recovered)));
        std::fs::write(root.join("unrelated.log"), "not a credential").unwrap();
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
            .await
            .is_err());

        let replacement = root.join("next.pem");
        std::os::unix::fs::symlink(&second, &replacement).unwrap();
        std::fs::rename(replacement, &current).unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                .await
                .unwrap(),
            Some(CredentialChangeEvent::Changed(_))
        ));
        std::fs::write(&second, "changed target").unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                .await
                .unwrap(),
            Some(CredentialChangeEvent::Changed(_))
        ));
        std::fs::write(trust.join("012abcde.0"), "changed trust").unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                .await
                .unwrap(),
            Some(CredentialChangeEvent::Changed(_))
        ));
    }

    #[tokio::test]
    async fn kubelet_secret_updates_notify_through_the_data_link_swap() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let volume = root.join("volume");
        let first = volume.join("..2024_01_01");
        let second = volume.join("..2024_01_02");
        for (generation, content) in [(&first, "first"), (&second, "second")] {
            std::fs::create_dir_all(generation).unwrap();
            for name in ["tls.crt", "tls.key", "ca.crt"] {
                std::fs::write(generation.join(name), content).unwrap();
            }
        }
        std::os::unix::fs::symlink("..2024_01_01", volume.join("..data")).unwrap();
        for name in ["tls.crt", "tls.key", "ca.crt"] {
            std::os::unix::fs::symlink(format!("..data/{name}"), volume.join(name)).unwrap();
        }
        let trust = root.join("trust");
        std::fs::create_dir(&trust).unwrap();
        let mut settings = crate::environment::Environment::parse(Default::default())
            .unwrap()
            .credentials;
        settings.certificate = volume.join("tls.crt");
        settings.key = volume.join("tls.key");
        settings.ca_file = volume.join("ca.crt");
        settings.ca_directory = trust;
        settings.debounce = std::time::Duration::from_millis(10);
        settings.reconcile_interval = std::time::Duration::from_secs(60);
        let mut stream = MountedCredentials::new(settings).subscribe().await.unwrap();
        assert!(matches!(stream.next().await, Some(CredentialChangeEvent::Recovered)));

        std::os::unix::fs::symlink("..2024_01_02", volume.join("..data_tmp")).unwrap();
        std::fs::rename(volume.join("..data_tmp"), volume.join("..data")).unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                .await
                .unwrap(),
            Some(CredentialChangeEvent::Changed(_))
        ));
    }

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

    #[tokio::test]
    async fn explicit_ca_file_works_without_default_ca_directory_and_fails_when_missing() {
        use std::collections::BTreeMap;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let sample_ca = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../lde/containers/config/certificates/ca.crt");
        let ca_file = root.join("custom-ca.pem");
        std::fs::copy(&sample_ca, &ca_file).unwrap();
        let identity = root.join("client.pem");
        std::fs::write(&identity, "placeholder").unwrap();

        let mut settings = crate::environment::Environment::parse(BTreeMap::from([(
            "TACACSD_TLS_CA_FILE".to_owned(),
            ca_file.to_str().unwrap().to_owned(),
        )]))
        .unwrap()
        .credentials;
        settings.certificate = identity.clone();
        settings.key = identity;
        settings.ca_directory = root.join("absent-default-trust-dir");
        assert!(settings.ca_file_required && !settings.ca_directory_required);

        let provider = MountedCredentials::new(settings.clone());
        let (_control, scope) = WorkScope::new(());
        let resolved = provider.authorities(&scope).unwrap();
        assert!(matches!(
            resolved,
            ResolvedCredential::CaCertificateBag(bag) if !bag.certificates.is_empty()
        ));
        assert!(provider.subscribe().await.is_ok());

        // An explicitly configured CA file that is missing still fails closed.
        std::fs::remove_file(&ca_file).unwrap();
        assert!(provider.authorities(&scope).is_err());
    }

    fn encode_pem_certificate(der: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::new();
        for chunk in der.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
            let i0 = usize::try_from((triple >> 18) & 0x3f).unwrap();
            let i1 = usize::try_from((triple >> 12) & 0x3f).unwrap();
            let i2 = usize::try_from((triple >> 6) & 0x3f).unwrap();
            let i3 = usize::try_from(triple & 0x3f).unwrap();
            encoded.push(char::from(ALPHABET[i0]));
            encoded.push(char::from(ALPHABET[i1]));
            encoded.push(if chunk.len() > 1 {
                char::from(ALPHABET[i2])
            } else {
                '='
            });
            encoded.push(if chunk.len() > 2 {
                char::from(ALPHABET[i3])
            } else {
                '='
            });
        }
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        assert_eq!(
            CertificateDer::from_pem_slice(pem.as_bytes())
                .unwrap()
                .as_ref(),
            der
        );
        pem
    }

    fn certificate_with_validity(
        sample_der: &[u8],
        not_before: std::time::SystemTime,
        not_after: std::time::SystemTime,
    ) -> String {
        use x509_cert::der::Encode;
        use x509_cert::time::{Time, Validity};

        let parsed = Certificate::from_der(sample_der).unwrap();
        let original = parsed.tbs_certificate().validity().to_der().unwrap();
        let replacement = Validity::<x509_cert::certificate::Rfc5280>::new(
            Time::try_from(not_before).unwrap(),
            Time::try_from(not_after).unwrap(),
        )
        .to_der()
        .unwrap();
        assert_eq!(original.len(), replacement.len());
        let offset = sample_der
            .windows(original.len())
            .position(|window| window == original.as_slice())
            .expect("validity sequence must appear in template certificate");
        let mut updated = sample_der.to_vec();
        updated[offset..offset + replacement.len()].copy_from_slice(&replacement);
        Certificate::from_der(&updated).expect("patched certificate must decode");
        encode_pem_certificate(&updated)
    }

    #[test]
    fn identity_intersects_validity_across_leaf_and_intermediates() {
        use std::time::{Duration, UNIX_EPOCH};

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let cert_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../lde/containers/config/certificates");
        let sample_cert_der = std::fs::read(cert_dir.join("client.crt.der")).unwrap();
        let key_path = root.join("client.key.der");
        std::fs::copy(cert_dir.join("client.key.der"), &key_path).unwrap();

        let t0 = UNIX_EPOCH + Duration::from_secs(1_950_000_000);
        let t1 = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let t2 = UNIX_EPOCH + Duration::from_secs(2_100_000_000);
        let t3 = UNIX_EPOCH + Duration::from_secs(2_200_000_000);
        let t4 = UNIX_EPOCH + Duration::from_secs(2_300_000_000);
        let t5 = UNIX_EPOCH + Duration::from_secs(2_400_000_000);

        let chain_path = root.join("client-chain.pem");
        let chain_pem = format!(
            "{}{}{}",
            certificate_with_validity(&sample_cert_der, t1, t4),
            certificate_with_validity(&sample_cert_der, t2, t5),
            certificate_with_validity(&sample_cert_der, t0, t3),
        );
        std::fs::write(&chain_path, chain_pem).unwrap();

        let mut settings = crate::environment::Environment::parse(Default::default())
            .unwrap()
            .credentials;
        settings.certificate = chain_path.clone();
        settings.key = key_path;
        let provider = MountedCredentials::new(settings);
        let ResolvedCredential::CertificateWithKey(material) = provider.identity().unwrap() else {
            panic!("expected certificate with key material");
        };
        assert_eq!(material.intermediates.len(), 2);
        assert_eq!(material.validity, CredentialValidity::new(Some(t2), Some(t3)).unwrap());

        // A disjoint intermediate window must fail closed.
        let disjoint_pem = format!(
            "{}{}",
            certificate_with_validity(&sample_cert_der, t0, t1),
            certificate_with_validity(&sample_cert_der, t2, t3),
        );
        std::fs::write(&chain_path, disjoint_pem).unwrap();
        assert!(provider.identity().is_err());
    }

    #[tokio::test]
    async fn ca_directory_kubelet_data_link_swap_notifies_immediately() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let identity_dir = root.join("identity");
        std::fs::create_dir(&identity_dir).unwrap();
        let cert_path = identity_dir.join("tls.crt");
        let ca_file = identity_dir.join("ca.crt");
        std::fs::write(&cert_path, "identity").unwrap();
        std::fs::write(&ca_file, "bundle").unwrap();

        let trust = root.join("trust");
        let first = trust.join("..2024_01_01");
        let second = trust.join("..2024_01_02");
        for (generation, content) in [(&first, "first-ca"), (&second, "second-ca")] {
            std::fs::create_dir_all(generation).unwrap();
            std::fs::write(generation.join("012abcde.0"), content).unwrap();
        }
        std::os::unix::fs::symlink("..2024_01_01", trust.join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/012abcde.0", trust.join("012abcde.0")).unwrap();

        let projection_directories = vec![identity_dir, trust.clone()];
        assert!(kubelet_projection_entry(&trust.join("..data"), &projection_directories));
        assert!(kubelet_projection_entry(&trust.join("..data_tmp"), &projection_directories));
        assert!(!kubelet_projection_entry(&root.join("..data"), &projection_directories));

        let mut settings = crate::environment::Environment::parse(Default::default())
            .unwrap()
            .credentials;
        settings.certificate = cert_path.clone();
        settings.key = cert_path;
        settings.ca_file = ca_file;
        settings.ca_directory = trust.clone();
        settings.debounce = std::time::Duration::from_millis(10);
        settings.reconcile_interval = std::time::Duration::from_secs(60);

        let mut stream = MountedCredentials::new(settings).subscribe().await.unwrap();
        assert!(matches!(stream.next().await, Some(CredentialChangeEvent::Recovered)));

        std::os::unix::fs::symlink("..2024_01_02", trust.join("..data_tmp")).unwrap();
        std::fs::rename(trust.join("..data_tmp"), trust.join("..data")).unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                .await
                .unwrap(),
            Some(CredentialChangeEvent::Changed(_))
        ));
    }
}
