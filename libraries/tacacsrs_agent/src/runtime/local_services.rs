//! The local services that the runtime applies now.
//!
//! A datastore change can contain new local services. The runtime prepares
//! that value and publishes the candidate together with the upstream servers
//! of the same change. Then the listener reconcilers bind, move, or stop the
//! local listeners.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::ensure;

use tacacsrs_config::local_services::{prepare_local_services, ListenerEndpoint, PreparedLocalServices};
use tacacsrs_config::tacacsrs::LocalServices;
use super::config_view::{ConfigPublisher, LocalServicesView};
use super::proxy_loop_guard::{ProxyGuardTarget, ProxyLoopGuard};

/// Local services with their prepared bind targets.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActiveLocalServices {
    settings: LocalServices,
    prepared: PreparedLocalServices,
}

impl ActiveLocalServices {
    /// Prepares local services.
    ///
    /// # Errors
    /// Returns an error when the local services are not valid.
    pub fn new(settings: LocalServices) -> anyhow::Result<Self> {
        let prepared = prepare_local_services(&settings)?;
        Ok(Self { settings, prepared })
    }

    /// Returns the canonical local services.
    #[must_use]
    pub const fn settings(&self) -> &LocalServices {
        &self.settings
    }

    /// Returns the prepared bind targets.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedLocalServices {
        &self.prepared
    }

    pub(crate) fn proxy_guard_target(&self) -> ProxyGuardTarget {
        match self.prepared.tacacs_proxy() {
            Some(endpoint) => ProxyGuardTarget::from_endpoint(Some(endpoint)),
            None if self.prepared.tacacs_proxy_enabled() => ProxyGuardTarget::Waiting,
            None => ProxyGuardTarget::Inactive,
        }
    }
}

/// Owns the active local services of the runtime.
pub(crate) struct LocalServicesState {
    publisher: ConfigPublisher<ActiveLocalServices>,
    proxy_loop_guard: ProxyLoopGuard,
    protected_paths: Mutex<Vec<PathBuf>>,
}

impl LocalServicesState {
    pub(crate) fn new(initial: ActiveLocalServices) -> Self {
        let proxy_loop_guard = ProxyLoopGuard::with_target(initial.proxy_guard_target());
        Self {
            publisher: ConfigPublisher::new(Arc::new(initial)),
            proxy_loop_guard,
            protected_paths: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn proxy_loop_guard(&self) -> &ProxyLoopGuard {
        &self.proxy_loop_guard
    }

    pub(crate) fn view(&self) -> LocalServicesView {
        self.publisher.view()
    }

    pub(crate) fn current(&self) -> Arc<ActiveLocalServices> {
        self.publisher.current()
    }

    /// Registers a protected file path that no Unix listener socket may replace.
    pub(crate) fn protect_path(&self, path: PathBuf) -> anyhow::Result<()> {
        let normalized = resolve_listener_path(&path).unwrap_or(path);
        ensure_not_protected(self.current().prepared(), std::slice::from_ref(&normalized))?;
        let mut protected = self
            .protected_paths
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !protected.contains(&normalized) {
            protected.push(normalized);
        }
        Ok(())
    }

    /// Prepares a candidate local-services snapshot.
    pub(crate) fn prepare_candidate(
        &self,
        source: &LocalServices,
    ) -> anyhow::Result<Arc<ActiveLocalServices>> {
        let candidate = ActiveLocalServices::new(source.clone())?;
        let protected = self
            .protected_paths
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        ensure_not_protected(candidate.prepared(), &protected)?;
        Ok(Arc::new(candidate))
    }

    /// Publishes new local services. An unchanged value does nothing.
    ///
    /// The proxy loop guard receives the new target before the listeners do.
    pub(crate) fn publish(&self, next: Arc<ActiveLocalServices>) {
        self.publisher.publish_with(next, |next| {
            self.proxy_loop_guard.configure(next.proxy_guard_target());
            log::info!("The runtime applies new local services");
        });
    }
}

fn ensure_not_protected(
    prepared: &PreparedLocalServices,
    protected: &[PathBuf],
) -> anyhow::Result<()> {
    if protected.is_empty() {
        return Ok(());
    }
    if let Some(path) = prepared.client_api() {
        ensure_listener_not_protected(path, protected)?;
    }
    if let Some(ListenerEndpoint::Unix(path)) = prepared.tacacs_proxy() {
        ensure_listener_not_protected(path, protected)?;
    }
    Ok(())
}

fn ensure_listener_not_protected(listener: &Path, protected: &[PathBuf]) -> anyhow::Result<()> {
    let resolved = resolve_listener_path(listener);
    for protected_path in protected {
        ensure!(
            listener != protected_path && resolved.as_deref() != Some(protected_path.as_path()),
            "Statistics destination cannot replace a listener socket"
        );
    }
    Ok(())
}

fn resolve_listener_path(listener: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = std::fs::canonicalize(listener) {
        return Some(canonical);
    }
    let (parent, name) = (listener.parent()?, listener.file_name()?);
    std::fs::canonicalize(parent)
        .ok()
        .map(|parent| parent.join(name))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn protected_statistics_path_rejects_bootstrap_and_live_unix_listener_candidates() {
        let directory = std::env::temp_dir().join(format!(
            "agent-local-services-protect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let alias_dir = directory.join("alias");
        std::os::unix::fs::symlink(&directory, &alias_dir).unwrap();

        let bootstrap_socket = directory.join("tacacs.sock");
        let stats_file = directory.join("statistics.json");
        let state = LocalServicesState::new(
            ActiveLocalServices::new(LocalServices {
                client_api_endpoint: bootstrap_socket.to_str().unwrap().to_owned(),
                ..LocalServices::default()
            })
            .unwrap(),
        );

        assert!(state.protect_path(bootstrap_socket.clone()).is_err());
        state.protect_path(stats_file.clone()).unwrap();

        // Rejects client_api targeting the protected path directly or via a symlinked directory.
        for candidate_path in [&stats_file, &alias_dir.join("statistics.json")] {
            let error = state
                .prepare_candidate(&LocalServices {
                    client_api_endpoint: candidate_path.to_str().unwrap().to_owned(),
                    ..LocalServices::default()
                })
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("cannot replace a listener socket"));
        }

        // Rejects tacacs_proxy Unix socket targeting the protected path.
        let proxy_error = state
            .prepare_candidate(&LocalServices {
                client_api_enabled: false,
                tacacs_proxy_enabled: true,
                tacacs_proxy_endpoint: Some(stats_file.to_str().unwrap().to_owned()),
                ..LocalServices::default()
            })
            .unwrap_err();
        assert!(proxy_error
            .to_string()
            .contains("cannot replace a listener socket"));

        // Accepts distinct Unix sockets and TCP proxy endpoints.
        let next_socket = directory.join("next.sock");
        assert!(state
            .prepare_candidate(&LocalServices {
                client_api_endpoint: next_socket.to_str().unwrap().to_owned(),
                tacacs_proxy_enabled: true,
                tacacs_proxy_endpoint: Some("127.0.0.1:4949".to_owned()),
                ..LocalServices::default()
            })
            .is_ok());

        std::fs::remove_dir_all(&directory).unwrap();
    }
}
