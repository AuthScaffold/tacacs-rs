//! SONiC credential provider with fixed, root-confined object namespaces.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tacacsrs_config::crypto_types::SymmetricKeyFormat;
use tacacsrs_credential_resolution::{
    CredentialKind, CredentialRequest, CredentialResolver, ProviderErrorKind, ResolutionError,
    ResolvedCredential,
};
use tacacsrs_credential_resolution::{SecretBytes, SymmetricKeyMaterial};

/// Production credential roots for the SONiC central agent.
#[derive(Clone)]
pub struct SonicCredentialRoots {
    epsk: PathBuf,
    acms: PathBuf,
}

impl SonicCredentialRoots {
    /// Production EPSK provider root.
    pub const DEFAULT_EPSK_ROOT: &'static str = "/etc/sonic/tacacs/credentials/epsk";
    /// Production ACMS certificate root reserved for a later schema revision.
    pub const DEFAULT_ACMS_ROOT: &'static str = "/etc/sonic/credentials";

    /// Creates provider roots that tests can replace.
    #[must_use]
    pub fn new(epsk: impl Into<PathBuf>, acms: impl Into<PathBuf>) -> Self {
        Self {
            epsk: epsk.into(),
            acms: acms.into(),
        }
    }

    /// Returns the EPSK root used during provider initialization.
    #[must_use]
    pub fn epsk(&self) -> &Path {
        &self.epsk
    }

    /// Returns the reserved ACMS root.
    #[must_use]
    pub fn acms(&self) -> &Path {
        &self.acms
    }
}

impl Default for SonicCredentialRoots {
    fn default() -> Self {
        Self::new(Self::DEFAULT_EPSK_ROOT, Self::DEFAULT_ACMS_ROOT)
    }
}

impl fmt::Debug for SonicCredentialRoots {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SonicCredentialRoots")
            .field("epsk", &"<redacted>")
            .field("acms", &"<redacted>")
            .finish()
    }
}

/// Ownership, mode, and size policy for EPSK objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SonicCredentialPolicy {
    expected_uid: u32,
    expected_gid: Option<u32>,
    root_mode: u32,
    file_mode: u32,
    max_epsk_bytes: usize,
}

impl SonicCredentialPolicy {
    /// Creates the production policy for a target-specific `aaaagent` group.
    #[must_use]
    pub const fn production(group_gid: u32) -> Self {
        Self {
            expected_uid: 0,
            expected_gid: Some(group_gid),
            root_mode: 0o750,
            file_mode: 0o640,
            max_epsk_bytes: 4096,
        }
    }

    /// Creates a policy for tests and non-production checks.
    #[must_use]
    pub const fn new(owner_uid: u32, group_gid: u32) -> Self {
        Self {
            expected_uid: owner_uid,
            expected_gid: Some(group_gid),
            root_mode: 0o750,
            file_mode: 0o640,
            max_epsk_bytes: 4096,
        }
    }

    /// Creates a production policy that trusts the root-owned directory group.
    #[must_use]
    pub const fn production_from_root_group() -> Self {
        Self {
            expected_uid: 0,
            expected_gid: None,
            root_mode: 0o750,
            file_mode: 0o640,
            max_epsk_bytes: 4096,
        }
    }
}

/// Sanitized provider initialization failure.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SonicCredentialInitializationError {
    /// The provider cannot open the EPSK root.
    RootUnavailable,
    /// The EPSK root metadata violates the configured policy.
    InvalidRootMetadata,
}

impl fmt::Display for SonicCredentialInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootUnavailable => formatter.write_str("SONiC EPSK provider root is unavailable"),
            Self::InvalidRootMetadata => {
                formatter.write_str("SONiC EPSK provider root metadata is invalid")
            }
        }
    }
}

impl std::error::Error for SonicCredentialInitializationError {}

/// Provider for SONiC central credential references.
pub struct SonicCredentialResolver {
    roots: SonicCredentialRoots,
    policy: SonicCredentialPolicy,
    epsk_root: Option<Arc<rustix::fd::OwnedFd>>,
}

impl SonicCredentialResolver {
    /// Opens the configured provider roots and makes sure that they are valid.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error if the platform is unsupported. It also
    /// returns an error if the EPSK root does not satisfy the metadata policy.
    pub fn open(
        roots: SonicCredentialRoots,
        policy: SonicCredentialPolicy,
    ) -> Result<Self, SonicCredentialInitializationError> {
        let (root, root_gid) = linux::open_root(roots.epsk(), policy)?;
        let policy = SonicCredentialPolicy {
            expected_gid: Some(root_gid),
            ..policy
        };
        Ok(Self {
            roots,
            policy,
            epsk_root: Some(Arc::new(root)),
        })
    }

    /// Creates a provider that opens roots and makes sure that they are valid
    /// during each reload.
    #[must_use]
    pub fn reloadable(roots: SonicCredentialRoots, policy: SonicCredentialPolicy) -> Self {
        Self {
            roots,
            policy,
            epsk_root: None,
        }
    }

    /// Returns the provider roots without exposing them through `Debug`.
    #[must_use]
    pub const fn roots(&self) -> &SonicCredentialRoots {
        &self.roots
    }
}

impl fmt::Debug for SonicCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SonicCredentialResolver")
            .field("roots", &self.roots)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CredentialResolver for SonicCredentialResolver {
    async fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> Result<ResolvedCredential, ResolutionError> {
        if request.kind() != CredentialKind::SymmetricKey {
            return Err(ResolutionError::provider(
                ProviderErrorKind::InvalidMaterial,
                request.context(),
            ));
        }
        let reference = request.reference().symmetric_key().ok_or_else(|| {
            ResolutionError::provider(ProviderErrorKind::InvalidMaterial, request.context())
        })?;

        let root = self.epsk_root.as_ref().map(Arc::clone);
        let roots = self.roots.clone();
        let configured_policy = self.policy;
        let reference = reference.to_owned();
        let bytes = tokio::task::spawn_blocking(move || {
            let (root, policy) = if let Some(root) = root {
                (root, configured_policy)
            } else {
                let (root, root_gid) = linux::open_root(roots.epsk(), configured_policy)
                    .map_err(map_initialization_error)?;
                (
                    Arc::new(root),
                    SonicCredentialPolicy {
                        expected_gid: Some(root_gid),
                        ..configured_policy
                    },
                )
            };
            linux::read_epsk(&root, &reference, policy)
        })
        .await
        .map_err(|_| ResolutionError::provider(ProviderErrorKind::Unavailable, request.context()))?
        .map_err(|kind| ResolutionError::provider(kind, request.context()))?;
        Ok(ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
            key_format: Some(SymmetricKeyFormat::OctetStringKeyFormat),
            key: SecretBytes::from_zeroizing(bytes),
        }))
    }
}

fn map_initialization_error(error: SonicCredentialInitializationError) -> ProviderErrorKind {
    match error {
        SonicCredentialInitializationError::RootUnavailable => ProviderErrorKind::Unavailable,
        SonicCredentialInitializationError::InvalidRootMetadata => {
            ProviderErrorKind::InvalidMaterial
        }
    }
}

mod linux {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use rustix::fd::OwnedFd;
    use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
    use zeroize::Zeroizing;

    use super::{SonicCredentialInitializationError, SonicCredentialPolicy};
    use tacacsrs_credential_resolution::ProviderErrorKind;

    pub(super) fn open_root(
        path: &Path,
        policy: SonicCredentialPolicy,
    ) -> Result<(OwnedFd, u32), SonicCredentialInitializationError> {
        let root = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SonicCredentialInitializationError::RootUnavailable)?;
        let stat = fstat(&root).map_err(|_| SonicCredentialInitializationError::RootUnavailable)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || stat.st_uid != policy.expected_uid
            || policy
                .expected_gid
                .is_some_and(|expected| stat.st_gid != expected)
            || stat.st_mode & 0o7777 != policy.root_mode
        {
            return Err(SonicCredentialInitializationError::InvalidRootMetadata);
        }
        Ok((root, stat.st_gid))
    }

    pub(super) fn read_epsk(
        root: &OwnedFd,
        reference: &str,
        policy: SonicCredentialPolicy,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderErrorKind> {
        read_epsk_with_hook(root, reference, policy, || {})
    }

    fn read_epsk_with_hook(
        root: &OwnedFd,
        reference: &str,
        policy: SonicCredentialPolicy,
        after_initial_metadata: impl FnOnce(),
    ) -> Result<Zeroizing<Vec<u8>>, ProviderErrorKind> {
        validate_object_id(reference)?;
        let fd = openat(
            root,
            reference,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_error)?;
        let before = fstat(&fd).map_err(|_| ProviderErrorKind::Unavailable)?;
        validate_file_metadata(&before, policy)?;
        after_initial_metadata();

        let mut file = File::from(fd);
        let mut bytes = Zeroizing::new(Vec::new());
        file.by_ref()
            .take((policy.max_epsk_bytes + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ProviderErrorKind::Unavailable)?;
        if bytes.len() > policy.max_epsk_bytes || bytes.len() < 16 {
            return Err(ProviderErrorKind::InvalidMaterial);
        }

        let after = file
            .metadata()
            .map_err(|_| ProviderErrorKind::Unavailable)?;
        if before.st_dev != after.dev()
            || before.st_ino != after.ino()
            || u64::try_from(before.st_size) != Ok(after.size())
            || before.st_mtime != after.mtime()
            || u64::try_from(after.mtime_nsec()) != Ok(before.st_mtime_nsec)
            || before.st_ctime != after.ctime()
            || u64::try_from(after.ctime_nsec()) != Ok(before.st_ctime_nsec)
        {
            return Err(ProviderErrorKind::Unavailable);
        }

        Ok(bytes)
    }

    fn validate_object_id(reference: &str) -> Result<(), ProviderErrorKind> {
        let mut bytes = reference.bytes();
        let Some(first) = bytes.next() else {
            return Err(ProviderErrorKind::InvalidMaterial);
        };
        if reference.len() > 64
            || !first.is_ascii_alphanumeric()
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ProviderErrorKind::InvalidMaterial);
        }
        Ok(())
    }

    fn validate_file_metadata(
        stat: &rustix::fs::Stat,
        policy: SonicCredentialPolicy,
    ) -> Result<(), ProviderErrorKind> {
        let size = usize::try_from(stat.st_size).map_err(|_| ProviderErrorKind::InvalidMaterial)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != policy.expected_uid
            || policy.expected_gid != Some(stat.st_gid)
            || stat.st_mode & 0o7777 != policy.file_mode
            || stat.st_nlink != 1
            || stat.st_size < 16
            || size > policy.max_epsk_bytes
        {
            return Err(ProviderErrorKind::InvalidMaterial);
        }
        Ok(())
    }

    fn map_open_error(error: rustix::io::Errno) -> ProviderErrorKind {
        match error {
            rustix::io::Errno::NOENT => ProviderErrorKind::NotFound,
            rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => ProviderErrorKind::AccessDenied,
            rustix::io::Errno::LOOP
            | rustix::io::Errno::NXIO
            | rustix::io::Errno::NODEV
            | rustix::io::Errno::ISDIR => ProviderErrorKind::InvalidMaterial,
            _ => ProviderErrorKind::Unavailable,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        use super::*;

        #[test]
        fn metadata_change_during_read_is_rejected_without_returning_bytes() {
            let temp = tempfile::tempdir().expect("temporary root");
            let root_path = temp.path().join("epsk");
            fs::create_dir(&root_path).expect("create root");
            fs::set_permissions(&root_path, fs::Permissions::from_mode(0o750))
                .expect("set root mode");
            let object_path = root_path.join("race-object");
            fs::write(&object_path, [0x41; 32]).expect("write object");
            fs::set_permissions(&object_path, fs::Permissions::from_mode(0o640))
                .expect("set object mode");
            let metadata = fs::metadata(&root_path).expect("root metadata");
            let policy = SonicCredentialPolicy::new(metadata.uid(), metadata.gid());
            let (root, _) = open_root(&root_path, policy).expect("open root");

            let outcome = read_epsk_with_hook(&root, "race-object", policy, || {
                fs::write(&object_path, [0x42; 48]).expect("replace open inode contents");
            });

            // Remove the secret owner before the assertion. This prevents a
            // regression from printing the bytes.
            assert_eq!(outcome.map(|_| ()).err(), Some(ProviderErrorKind::Unavailable));
        }

        #[test]
        fn successful_read_returns_a_zeroizing_owner() {
            let temp = tempfile::tempdir().expect("temporary root");
            let root_path = temp.path().join("epsk");
            fs::create_dir(&root_path).expect("create root");
            fs::set_permissions(&root_path, fs::Permissions::from_mode(0o750))
                .expect("set root mode");
            let object_path = root_path.join("good-object");
            fs::write(&object_path, [0x41; 32]).expect("write object");
            fs::set_permissions(&object_path, fs::Permissions::from_mode(0o640))
                .expect("set object mode");
            let metadata = fs::metadata(&root_path).expect("root metadata");
            let policy = SonicCredentialPolicy::new(metadata.uid(), metadata.gid());
            let (root, _) = open_root(&root_path, policy).expect("open root");

            // The explicit type makes sure that this path cannot return a plain Vec<u8>.
            let secret: Zeroizing<Vec<u8>> =
                read_epsk_with_hook(&root, "good-object", policy, || {}).expect("read object");
            assert_eq!(secret.as_slice(), vec![0x41u8; 32]);
        }
    }
}
