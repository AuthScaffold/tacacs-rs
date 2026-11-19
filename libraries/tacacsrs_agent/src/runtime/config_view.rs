//! Read-only views of the configuration that the runtime applies now.
//!
//! The runtime accepts each configuration section as part of a candidate. A
//! [`ConfigView`] gives the accepted value of one section to a component. The
//! component reads the current value or waits for the next accepted value. The
//! component never sees a value that the runtime rejected.
//!
//! The host registers each view in the dependency container. A component that
//! needs a section takes the view as a dependency and builds its own prepared
//! values from the section.

use std::sync::Arc;

use tokio::sync::watch;

use super::ActiveLocalServices;

/// A read-only view of one accepted configuration section.
///
/// Each clone sees each accepted change. A component that is slower than the
/// changes sees only the most recent value.
#[derive(Debug)]
pub struct ConfigView<T> {
    receiver: watch::Receiver<Arc<T>>,
}

impl<T> Clone for ConfigView<T> {
    fn clone(&self) -> Self {
        Self {
            receiver: self.receiver.clone(),
        }
    }
}

impl<T> ConfigView<T> {
    /// Returns the accepted value.
    #[must_use]
    pub fn current(&self) -> Arc<T> {
        Arc::clone(&self.receiver.borrow())
    }

    /// Returns an independent receiver of the accepted values.
    ///
    /// Use [`watch::Receiver::borrow_and_update`] to read the value, and
    /// [`watch::Receiver::changed`] to wait for the next accepted value. The
    /// receiver reports an error after the runtime stops.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Arc<T>> {
        self.receiver.clone()
    }
}

/// The accepted local services and their prepared bind targets.
pub type LocalServicesView = ConfigView<ActiveLocalServices>;

/// The accepted `tacacsrs:runtime-policy` container as validated values.
pub type RuntimePolicyView = ConfigView<crate::RuntimePolicy>;

/// Owns the accepted value of one configuration section.
pub(crate) struct ConfigPublisher<T> {
    sender: watch::Sender<Arc<T>>,
}

impl<T: PartialEq> ConfigPublisher<T> {
    pub(crate) fn new(initial: Arc<T>) -> Self {
        let (sender, _) = watch::channel(initial);
        Self { sender }
    }

    pub(crate) fn view(&self) -> ConfigView<T> {
        ConfigView {
            receiver: self.sender.subscribe(),
        }
    }

    pub(crate) fn current(&self) -> Arc<T> {
        Arc::clone(&self.sender.borrow())
    }

    /// Publishes a new value and returns `true` if the value changed.
    ///
    /// The `before` closure runs only for a changed value, before the views
    /// see the value.
    pub(crate) fn publish_with(&self, next: Arc<T>, before: impl FnOnce(&T)) -> bool {
        self.sender.send_if_modified(|current| {
            if **current == *next {
                return false;
            }
            before(&next);
            *current = next;
            true
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn views_see_changed_values_only() {
        let publisher = ConfigPublisher::new(Arc::new(1));
        let view = publisher.view();
        let mut changes = view.subscribe();
        assert_eq!(**changes.borrow_and_update(), 1);

        assert!(!publisher.publish_with(Arc::new(1), |_| unreachable!()));
        assert!(!changes.has_changed().unwrap());

        let mut seen = None;
        assert!(publisher.publish_with(Arc::new(2), |next| seen = Some(*next)));
        assert_eq!(seen, Some(2));
        changes.changed().await.unwrap();
        assert_eq!(**changes.borrow_and_update(), 2);
        assert_eq!(*view.current(), 2);
        assert_eq!(*publisher.current(), 2);
    }
}
