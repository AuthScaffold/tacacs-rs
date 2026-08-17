//! Unix domain socket IPC listener.

use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use rustix::fs::{FlockOperation, flock};
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgentServer;
use tokio::sync::watch;
use tokio_stream::wrappers::UnixListenerStream;

use crate::runtime::{ListenerRegistration, RuntimeHealthSnapshot, ShutdownReceiver};
use crate::services::client_api::health::StandardHealth;
use crate::services::client_api::ClientApiService;

/// Runs the Unix domain socket IPC listener until shutdown starts.
///
/// After a shutdown signal, the gRPC server stops accepting requests. It waits
/// for active RPC handlers to finish and then removes the socket path.
pub(crate) async fn serve(
    path: &Path,
    service: ClientApiService,
    socket_mode: u32,
    shutdown: ShutdownReceiver,
    registration: ListenerRegistration,
    health: watch::Receiver<RuntimeHealthSnapshot>,
) -> anyhow::Result<()> {
    let (listener, socket_guard) = prepare_unix_listener(path, socket_mode).await?;
    let incoming = UnixListenerStream::new(listener);
    let (standard_health, health_service) = StandardHealth::new(health).await;
    let health_task = tokio::spawn(standard_health.run(shutdown.clone()));
    registration.mark_bound();

    log::info!("The IPC listener accepts clients on Unix domain socket {}", path.display());

    tonic::transport::Server::builder()
        .add_service(TacacsAgentServer::new(service.grpc_service()))
        .add_service(health_service)
        .serve_with_incoming_shutdown(incoming, shutdown.wait())
        .await
        .with_context(|| format!("Unix IPC server {} failed", path.display()))?;

    log::info!("Received a shutdown signal; draining active IPC requests");
    service.wait_for_active_requests().await;
    health_task
        .await
        .context("Standard gRPC health bridge failed")?;
    socket_guard.cleanup("Unix domain socket").await?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct UnixSocketCleanupGuard {
    path: PathBuf,
    identity: (u64, u64),
    // Keep the exclusive lock until the listener or guard is dropped.
    #[allow(dead_code)]
    lock: std::fs::File,
    should_cleanup: bool,
}

impl UnixSocketCleanupGuard {
    fn new(path: &Path, identity: (u64, u64), lock: std::fs::File) -> Self {
        Self {
            path: path.to_owned(),
            identity,
            lock,
            should_cleanup: true,
        }
    }

    pub(crate) async fn cleanup(mut self, label: &str) -> anyhow::Result<()> {
        if !self.owns_current_path() {
            log::debug!(
                "{label} {} belongs to a different instance; leaving it in place",
                self.path.display()
            );
            self.disarm();
            return Ok(());
        }
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => {
                log::debug!("Removed {label} {}", self.path.display());
                self.disarm();
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                log::debug!("{label} {} is already removed", self.path.display());
                self.disarm();
                Ok(())
            }
            Err(error) => Err(error)
                .with_context(|| format!("Failed to remove {label} {}", self.path.display())),
        }
    }

    // A stale or replacement entry has a different (dev, ino). Do not remove it.
    fn owns_current_path(&self) -> bool {
        socket_identity(&self.path).is_ok_and(|identity| identity == self.identity)
    }

    fn disarm(&mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for UnixSocketCleanupGuard {
    fn drop(&mut self) {
        if !self.should_cleanup {
            return;
        }
        if !self.owns_current_path() {
            log::debug!(
                "Unix domain socket {} belongs to a different instance; leaving it in place",
                self.path.display()
            );
            return;
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                log::debug!(
                    "Removed Unix domain socket {} during cancellation",
                    self.path.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                log::debug!("Unix domain socket {} is already removed", self.path.display());
            }
            Err(error) => {
                log::warn!(
                    "Failed to remove Unix domain socket {} during cancellation: {error}",
                    self.path.display()
                );
            }
        }
    }
}

/// Creates a Unix domain socket listener.
///
/// The returned guard holds an exclusive advisory lock on `<path>.lock`. This
/// lock prevents cooperating service instances from using the same path at the
/// same time. This function removes only a stale Unix domain socket. It does not
/// remove regular files, directories, symbolic links, or devices.
pub(crate) async fn prepare_unix_listener(
    path: &Path,
    socket_mode: u32,
) -> anyhow::Result<(tokio::net::UnixListener, UnixSocketCleanupGuard)> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.with_context(|| {
            format!("Failed to create the Unix domain socket directory {}", parent.display())
        })?;
    }

    let lock = acquire_instance_lock(path)?;
    reconcile_existing_socket_path(path).await?;

    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("Failed to bind Unix domain socket {}", path.display()))?;
    let identity = socket_identity(path).with_context(|| {
        format!("Failed to record the identity of Unix domain socket {}", path.display())
    })?;
    let socket_guard = UnixSocketCleanupGuard::new(path, identity, lock);

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode)).with_context(
        || format!("Failed to set permissions on Unix domain socket {}", path.display()),
    )?;

    log::info!("Bound Unix domain socket {}", path.display());
    Ok((listener, socket_guard))
}

/// Returns the advisory-lock path for one Unix domain socket.
fn instance_lock_path(path: &Path) -> PathBuf {
    let mut lock_name = path.as_os_str().to_owned();
    lock_name.push(".lock");
    PathBuf::from(lock_name)
}

/// Takes the exclusive advisory lock for `path`.
///
/// The caller holds the returned file for the listener lifetime. Dropping the
/// file or stopping the process releases the lock.
fn acquire_instance_lock(path: &Path) -> anyhow::Result<std::fs::File> {
    let lock_path = instance_lock_path(path);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .with_context(|| {
            format!("Failed to open Unix domain socket lock {}", lock_path.display())
        })?;
    match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(lock),
        Err(rustix::io::Errno::WOULDBLOCK) => {
            bail!("Unix domain socket {} is locked by another service instance", path.display())
        }
        Err(error) => Err(anyhow::Error::new(error))
            .with_context(|| format!("Failed to lock Unix domain socket {}", path.display())),
    }
}

/// Removes a stale, unowned Unix domain socket at `path`.
///
/// The caller must hold the instance lock. This function does not remove other
/// file types.
async fn reconcile_existing_socket_path(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to inspect Unix domain socket path {}", path.display())
            });
        }
    };

    if !metadata.file_type().is_socket() {
        bail!("Cannot remove {} because it is not a Unix domain socket", path.display());
    }

    match tokio::net::UnixStream::connect(path).await {
        Ok(_) => bail!(
            "Unix domain socket {} already accepts connections; another service instance can be active",
            path.display()
        ),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            log::info!(
                "Removing stale Unix domain socket {}",
                path.display()
            );
            tokio::fs::remove_file(path)
                .await
                .with_context(|| {
                    format!("Failed to remove stale Unix domain socket {}", path.display())
                })
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "Cannot remove Unix domain socket {} because its state is unknown",
                path.display()
            )
        }),
    }
}

/// Returns the `(dev, ino)` identity of a Unix domain socket.
fn socket_identity(path: &Path) -> anyhow::Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect Unix domain socket {}", path.display()))?;
    if !metadata.file_type().is_socket() {
        bail!("Path {} is not a Unix domain socket", path.display());
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileTypeExt;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::prepare_unix_listener;

    fn test_socket_path(socket_name: &str) -> PathBuf {
        let unique = format!(
            "{}-{}-{}.sock",
            socket_name,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("the clock must be after the Unix epoch")
                .as_nanos()
        );
        PathBuf::from("/tmp").join(unique)
    }

    async fn cleanup_paths(path: &Path) {
        let _ = tokio::fs::remove_file(path).await;
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let _ = tokio::fs::remove_file(PathBuf::from(lock_name)).await;
    }

    fn is_socket(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or file-system I/O.
    async fn rejects_active_socket_path() {
        let path = test_socket_path("tacacs-active-socket");
        let existing = tokio::net::UnixListener::bind(&path).unwrap();

        let error = prepare_unix_listener(&path, 0o660).await.unwrap_err();

        assert!(error.to_string().contains("already accepts connections"));
        assert!(is_socket(&path));
        drop(existing);
        cleanup_paths(&path).await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or file-system I/O.
    async fn replaces_stale_socket_and_cleanup_removes_it() {
        let path = test_socket_path("tacacs-stale-socket");
        let stale = tokio::net::UnixListener::bind(&path).unwrap();
        drop(stale);

        let (listener, guard) = prepare_unix_listener(&path, 0o660).await.unwrap();
        assert!(is_socket(&path));

        drop(listener);
        guard.cleanup("Unix domain socket").await.unwrap();
        assert!(!tokio::fs::try_exists(&path).await.unwrap());
        cleanup_paths(&path).await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support file-system I/O.
    async fn refuses_to_remove_regular_file() {
        let path = test_socket_path("tacacs-regular-file");
        tokio::fs::write(&path, b"not a socket").await.unwrap();

        let error = prepare_unix_listener(&path, 0o660).await.unwrap_err();

        assert!(error.to_string().contains("not a Unix domain socket"));
        assert!(tokio::fs::try_exists(&path).await.unwrap());
        cleanup_paths(&path).await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support file-system I/O.
    async fn refuses_to_remove_symlink() {
        let path = test_socket_path("tacacs-symlink");
        let target = test_socket_path("tacacs-symlink-target");
        tokio::fs::write(&target, b"target").await.unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = prepare_unix_listener(&path, 0o660).await.unwrap_err();

        assert!(error.to_string().contains("not a Unix domain socket"));
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(tokio::fs::try_exists(&target).await.unwrap());
        cleanup_paths(&path).await;
        cleanup_paths(&target).await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or file-system I/O.
    async fn two_concurrent_starters_only_one_binds() {
        let path = test_socket_path("tacacs-concurrent");

        let (listener, guard) = prepare_unix_listener(&path, 0o660).await.unwrap();

        let error = prepare_unix_listener(&path, 0o660).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("locked by another service instance"));
        assert!(is_socket(&path));

        drop(listener);
        drop(guard);
        cleanup_paths(&path).await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or file-system I/O.
    async fn cleanup_leaves_successor_socket_untouched() {
        let path = test_socket_path("tacacs-successor");
        let moved = test_socket_path("tacacs-successor-moved");

        let (listener, guard) = prepare_unix_listener(&path, 0o660).await.unwrap();
        // Move this socket to keep its inode allocated. The replacement at the
        // original path then has a different inode.
        tokio::fs::rename(&path, &moved).await.unwrap();
        let successor = tokio::net::UnixListener::bind(&path).unwrap();

        // The old guard must not remove the replacement, which has a different inode.
        guard.cleanup("Unix domain socket").await.unwrap();
        assert!(is_socket(&path));

        drop(listener);
        drop(successor);
        cleanup_paths(&path).await;
        cleanup_paths(&moved).await;
    }
}
