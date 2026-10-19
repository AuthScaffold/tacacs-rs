//! Registered provider work, independent of any scheduler or async runtime.

use std::fmt;
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicBool, Ordering};

struct WorkState {
    sealed: Mutex<bool>,
    quiet: Arc<AtomicBool>,
    owner: Option<Box<dyn Send + Sync>>,
}

impl Drop for WorkState {
    fn drop(&mut self) {
        drop(self.owner.take());
        self.quiet.store(true, Ordering::Release);
    }
}

/// A lease that retains registered work and its queued result.
///
/// Providers must register a lease before they queue owned work that can outlive
/// `resolve`. The actual worker and its unconsumed result must retain that lease.
/// OS and SDK internals that a provider cannot observe are outside this contract.
///
/// ```
/// use tacacsrs_credential_resolution::WorkScope;
/// let (control, root) = WorkScope::new(());
/// let work = root.register().expect("scope is open");
/// control.seal();
/// drop(root);
/// assert!(!control.is_quiet());
/// drop(work);
/// assert!(control.is_quiet());
/// ```
///
/// A lease cannot be cloned, so sealing blocks every new lease:
///
/// ```compile_fail
/// use tacacsrs_credential_resolution::WorkScope;
/// fn duplicate(lease: WorkScope) -> (WorkScope, WorkScope) {
///     (lease.clone(), lease)
/// }
/// ```
pub struct WorkScope(Arc<WorkState>);

/// Sealing authority and quiet observation, without a work lease.
///
/// The observer does not keep capacity occupied. Sealing cannot force quiet.
pub struct WorkScopeControl {
    state: Weak<WorkState>,
    quiet: Arc<AtomicBool>,
}

impl WorkScope {
    /// Holds an opaque owner until the last root, work, or result lease drops.
    ///
    /// The owner's destructor must not block, panic, require a runtime, or
    /// reenter coordinator state. Scheduler permits belong in this owner.
    #[must_use]
    pub fn new(owner: impl Send + Sync + 'static) -> (WorkScopeControl, Self) {
        let quiet = Arc::new(AtomicBool::new(false));
        let state = Arc::new(WorkState {
            sealed: Mutex::new(false),
            quiet: Arc::clone(&quiet),
            owner: Some(Box::new(owner)),
        });
        (
            WorkScopeControl {
                state: Arc::downgrade(&state),
                quiet,
            },
            Self(state),
        )
    }

    /// Creates a caller-owned scope without a scheduler or global budget.
    #[must_use]
    pub fn unowned() -> Self {
        Self::new(()).1
    }

    /// Registers work before it can enter a queue or start execution.
    ///
    /// Returns `None` after cancellation seals the scope. Move a lease to
    /// transfer it. Every additional lease must come from this method.
    #[must_use]
    pub fn register(&self) -> Option<Self> {
        let sealed = self
            .0
            .sealed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (!*sealed).then(|| Self(Arc::clone(&self.0)))
    }
}

impl WorkScopeControl {
    /// Prevents registration of new work without releasing outstanding leases.
    pub fn seal(&self) {
        if let Some(state) = self.state.upgrade() {
            *state
                .sealed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        }
    }

    /// Returns true only after every lease and the held owner are released.
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.quiet.load(Ordering::Acquire)
    }
}

impl fmt::Debug for WorkScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("WorkScope").finish_non_exhaustive()
    }
}

impl fmt::Debug for WorkScopeControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkScopeControl")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use super::*;

    struct Owner(Arc<AtomicUsize>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn registered_work_last_drop_releases_owner_exactly_once() {
        let releases = Arc::new(AtomicUsize::new(0));
        let (control, root) = WorkScope::new(Owner(releases.clone()));
        let worker = root.register().unwrap();
        control.seal();
        assert!(root.register().is_none());
        drop(root);
        assert!(!control.is_quiet());
        assert_eq!(releases.load(Ordering::SeqCst), 0);
        drop(worker);
        assert!(control.is_quiet());
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        assert!(!format!("{control:?}").contains("Owner"));
    }

    #[test]
    fn registered_work_multithread_result_and_unwind_lifetimes() {
        let releases = Arc::new(AtomicUsize::new(0));
        let (control, root) = WorkScope::new(Owner(releases.clone()));
        let worker = root.register().unwrap();
        let job = std::thread::spawn(move || worker);
        control.seal();
        drop(root);
        let result = job.join().unwrap();
        assert!(!control.is_quiet());
        drop(result);
        assert!(control.is_quiet());
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        let (control, root) = WorkScope::new(Owner(releases.clone()));
        let worker = root.register().unwrap();
        drop(root);
        assert!(std::thread::spawn(move || {
            let _worker = worker;
            panic!("test unwind");
        })
        .join()
        .is_err());
        assert!(control.is_quiet());
        assert_eq!(releases.load(Ordering::SeqCst), 2);
    }
}
