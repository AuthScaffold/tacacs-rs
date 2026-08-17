#![doc = include_str!("../README.md")]
#![allow(clippy::doc_markdown)]

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures_core::Stream;
use tacacsrs_config::{TacacsPlus, ValidationOptions};
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::StreamExt;

/// Description of how the configuration changed between two snapshots.
///
/// Each [`ConfigChange`] contains the complete new [`TacacsPlus`] snapshot.
/// Consumers must treat the snapshot as authoritative. They can use this delta
/// for an incremental update or rebuild from the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigDelta {
    /// Server names present in the new snapshot but not in the previous one.
    pub added_servers: Vec<String>,
    /// Server names present in the previous snapshot but not in the new one.
    pub removed_servers: Vec<String>,
    /// Server names whose definitions changed between snapshots.
    pub modified_servers: Vec<String>,
    /// `true` when root data such as a shared credential bundle changed.
    ///
    /// If this field is `true`, consumers must use the complete configuration.
    pub root_metadata_changed: bool,
}

impl ConfigDelta {
    /// Returns `true` if the delta contains no server-level or root-level changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added_servers.is_empty()
            && self.removed_servers.is_empty()
            && self.modified_servers.is_empty()
            && !self.root_metadata_changed
    }

    /// Computes the delta between the previous and new snapshots.
    ///
    /// Structural inequality of matching
    /// [`tacacsrs_config::TacacsPlusServer`] values means that a server changed.
    /// A backend can construct [`ConfigDelta`] directly for a finer delta.
    #[must_use]
    pub fn diff(previous: Option<&TacacsPlus>, new: &TacacsPlus) -> Self {
        let Some(previous) = previous else {
            return Self {
                added_servers: new.server.iter().map(|s| s.name.clone()).collect(),
                removed_servers: Vec::new(),
                modified_servers: Vec::new(),
                root_metadata_changed: !new.client_credentials.is_empty()
                    || !new.server_credentials.is_empty(),
            };
        };

        let mut added = Vec::new();
        let mut modified = Vec::new();
        for server in &new.server {
            match previous.server.iter().find(|s| s.name == server.name) {
                None => added.push(server.name.clone()),
                Some(previous_server) if previous_server != server => {
                    modified.push(server.name.clone());
                }
                _ => {}
            }
        }

        let removed = previous
            .server
            .iter()
            .filter(|prev| !new.server.iter().any(|s| s.name == prev.name))
            .map(|s| s.name.clone())
            .collect::<Vec<_>>();

        let root_metadata_changed = previous.client_credentials != new.client_credentials
            || previous.server_credentials != new.server_credentials;

        Self {
            added_servers: added,
            removed_servers: removed,
            modified_servers: modified,
            root_metadata_changed,
        }
    }
}

/// Configuration change from a [`ConfigDatastore`].
///
/// Each event contains the latest complete, validated [`TacacsPlus`] snapshot.
/// Consumers can use `delta` for incremental processing.
#[derive(Debug, Clone)]
pub struct ConfigChange {
    /// The new validated configuration.
    pub config: Arc<TacacsPlus>,
    /// Changes that the backend detected from the previous snapshot.
    pub delta: ConfigDelta,
}

/// Typed event emitted by a datastore change subscription.
#[derive(Debug, Clone)]
pub enum ConfigChangeEvent {
    /// A complete validated candidate snapshot is available.
    Changed(ConfigChange),
    /// The datastore detected a change but rejected the candidate.
    ///
    /// Backends log the error locally. This event has no error text or
    /// configuration value. Thus, health consumers cannot expose addresses,
    /// credential references, or secrets.
    CandidateRejected,
    /// A validated host-binding setting changed but cannot be applied live.
    ///
    /// Bound resources stay active until the process restarts. This event does
    /// not contain configuration values.
    RestartRequired {
        /// Whether the current validated settings differ from bound resources.
        required: bool,
    },
}

/// Stream of [`ConfigChangeEvent`] values returned by [`ConfigDatastore::subscribe`].
pub type ConfigChangeStream = Pin<Box<dyn Stream<Item = ConfigChangeEvent> + Send + 'static>>;

/// Behavior the runtime applies when the initial datastore load fails.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InitialLoadPolicy {
    /// Return the load error to the operator and stop startup.
    FailFast,
    /// Retry until a valid snapshot is available or shutdown is requested.
    RetryUntilAvailable,
}

/// Change-notification guarantees provided by a datastore instance.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ChangeNotificationMode {
    /// The datastore is immutable for the lifetime of the process.
    None,
    /// The datastore maintains a continuous subscription that must be restored
    /// if setup fails or its stream ends.
    Continuous,
}

/// Runtime behavior declared by a [`ConfigDatastore`] instance.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DatastoreRuntimePolicy {
    /// Initial-load failure behavior.
    pub initial_load: InitialLoadPolicy,
    /// Change-notification behavior.
    pub change_notifications: ChangeNotificationMode,
}

impl DatastoreRuntimePolicy {
    /// Creates a datastore runtime policy.
    #[must_use]
    pub const fn new(
        initial_load: InitialLoadPolicy,
        change_notifications: ChangeNotificationMode,
    ) -> Self {
        Self {
            initial_load,
            change_notifications,
        }
    }
}

/// Source of TACACS+ configuration for the agent runtime.
///
/// Implementations supply initial configuration through [`load`] and later
/// events through [`subscribe`]. Backends translate vendor formats into the
/// YANG-aligned [`TacacsPlus`] structure. They return an error when validation
/// rejects input.
///
/// [`load`]: ConfigDatastore::load
/// [`subscribe`]: ConfigDatastore::subscribe
#[async_trait]
pub trait ConfigDatastore: Send + Sync + 'static {
    /// Declares how the runtime must supervise this datastore.
    ///
    /// A file-backed datastore can be immutable when it has no referenced
    /// paths. It requires continuous monitoring when configuration depends on
    /// files.
    fn runtime_policy(&self) -> DatastoreRuntimePolicy;

    /// Returns the validation policy already used to accept source snapshots.
    ///
    /// The default is strict. Backends with an explicit compatibility contract
    /// override this so final materialized validation uses the same policy.
    fn validation_options(&self) -> ValidationOptions {
        ValidationOptions::default()
    }

    /// Load the current configuration snapshot.
    ///
    /// The runtime calls this method at startup. Callers can use it again to
    /// read the configuration without a subscription.
    ///
    /// # Errors
    ///
    /// Returns an error if the backing store cannot be reached or if the
    /// retrieved configuration fails validation.
    async fn load(&self) -> anyhow::Result<TacacsPlus>;

    /// Subscribe to configuration change events.
    ///
    /// The stream emits a [`ConfigChangeEvent`] after each relevant datastore
    /// change. Each [`ConfigChangeEvent::Changed`] event contains the latest
    /// complete snapshot. Callers can use its delta for an incremental update.
    /// If the delta is not sufficient, callers must rebuild from the snapshot.
    /// Backends without notifications return an empty stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the subscription cannot be established (for
    /// example, the backing store is unreachable). Implementations that do
    /// not support change notifications return an empty stream rather than
    /// failing.
    async fn subscribe(&self) -> anyhow::Result<ConfigChangeStream>;

    /// Returns a human-readable label for the datastore implementation.
    ///
    /// Operator logs use this label to identify the datastore, for example
    /// `"static"` or `"sonic-configdb"`.
    fn label(&self) -> &'static str;
}

/// In-memory [`ConfigDatastore`] for CLI/file/test workflows.
///
/// `StaticDatastore` holds one `TacacsPlus` snapshot for the process lifetime.
/// [`subscribe`](ConfigDatastore::subscribe) returns an empty stream.
#[derive(Debug, Clone)]
pub struct StaticDatastore {
    config: Arc<TacacsPlus>,
    label: &'static str,
}

impl StaticDatastore {
    /// Creates a static datastore with validated configuration.
    #[must_use]
    pub fn new(config: TacacsPlus) -> Self {
        Self::with_label(config, "static")
    }

    /// Creates a static datastore with a caller-supplied label.
    ///
    /// [`ConfigDatastore::label`] returns this label for operator logs.
    #[must_use]
    pub fn with_label(config: TacacsPlus, label: &'static str) -> Self {
        Self {
            config: Arc::new(config),
            label,
        }
    }
}

#[async_trait]
impl ConfigDatastore for StaticDatastore {
    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None)
    }

    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        Ok((*self.config).clone())
    }

    async fn subscribe(&self) -> anyhow::Result<ConfigChangeStream> {
        Ok(Box::pin(tokio_stream::empty()))
    }

    fn label(&self) -> &'static str {
        self.label
    }
}

/// Converts a `tokio::sync::watch` channel into a change stream.
///
/// The first channel value is the initial snapshot. The stream does not publish
/// it as a change. Later updates contain a [`ConfigChange`] with a delta from
/// the previous snapshot.
#[must_use]
pub fn watch_to_change_stream(
    receiver: watch::Receiver<Option<Arc<TacacsPlus>>>,
) -> ConfigChangeStream {
    let mut previous: Option<Arc<TacacsPlus>> = receiver.borrow().clone();
    let stream = WatchStream::from_changes(receiver).filter_map(move |snapshot| {
        let snapshot = snapshot?;
        let delta = ConfigDelta::diff(previous.as_deref(), &snapshot);
        let change = ConfigChange {
            config: Arc::clone(&snapshot),
            delta,
        };
        previous = Some(snapshot);
        Some(ConfigChangeEvent::Changed(change))
    });
    Box::pin(stream)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use tacacsrs_config::{TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};

    fn sample_config(addr: &str) -> TacacsPlus {
        TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new("primary", TacacsPlusServerType::all(), addr, 49)
                    .with_shared_secret("topsecret"),
            )
            .build()
            .expect("sample configuration must be valid")
    }

    #[tokio::test]
    async fn static_datastore_returns_config_and_empty_stream() {
        let config = sample_config("192.0.2.1");
        let store = StaticDatastore::new(config.clone());
        let loaded = store.load().await.expect("load must succeed");
        assert_eq!(loaded.server.len(), 1);
        assert_eq!(store.label(), "static");
        assert_eq!(
            store.runtime_policy(),
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None,)
        );

        let mut stream = store.subscribe().await.expect("subscription must succeed");
        assert!(stream.next().await.is_none(), "static stream must be empty");
    }

    #[test]
    fn delta_detects_added_modified_and_removed_servers() {
        let mut previous = sample_config("192.0.2.1");
        previous.server.push(
            TacacsPlusServerBuilder::new("secondary", TacacsPlusServerType::all(), "192.0.2.2", 49)
                .with_shared_secret("topsecret")
                .build(),
        );

        let mut new = sample_config("192.0.2.1");
        // Modify the primary server.
        new.server[0].timeout = 10;
        // Add a tertiary server.
        new.server.push(
            TacacsPlusServerBuilder::new("tertiary", TacacsPlusServerType::all(), "192.0.2.3", 49)
                .with_shared_secret("topsecret")
                .build(),
        );
        // Remove the secondary server.

        let delta = ConfigDelta::diff(Some(&previous), &new);
        assert_eq!(delta.added_servers, vec!["tertiary"]);
        assert_eq!(delta.removed_servers, vec!["secondary"]);
        assert_eq!(delta.modified_servers, vec!["primary"]);
        assert!(!delta.root_metadata_changed);
        assert!(!delta.is_empty());
    }

    #[test]
    fn delta_against_no_previous_marks_all_added() {
        let new = sample_config("192.0.2.1");
        let delta = ConfigDelta::diff(None, &new);
        assert_eq!(delta.added_servers, vec!["primary"]);
        assert!(delta.removed_servers.is_empty());
        assert!(delta.modified_servers.is_empty());
        assert!(!delta.root_metadata_changed);
    }

    #[test]
    fn delta_detects_shared_secret_only_change_without_serialization() {
        let previous = sample_config("192.0.2.1");
        let mut new = sample_config("192.0.2.1");
        new.server[0] =
            TacacsPlusServerBuilder::new("primary", TacacsPlusServerType::all(), "192.0.2.1", 49)
                .with_shared_secret("replacement-secret")
                .build();

        let delta = ConfigDelta::diff(Some(&previous), &new);

        assert_eq!(delta.modified_servers, vec!["primary"]);
    }

    #[test]
    fn delta_detects_inline_epsk_key_only_change_without_serialization() {
        let previous = tacacsrs_config::parse_yang_json(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [{
                        "name": "epsk",
                        "server-type": "accounting",
                        "address": "192.0.2.1",
                        "port": 49,
                        "client-identity": {
                            "tls13-epsk": {
                                "inline-definition": {
                                    "cleartext-symmetric-key": "MDEyMzQ1Njc4OWFiY2RlZg=="
                                },
                                "external-identity": "client"
                            }
                        }
                    }]
                }
            }"#,
        )
        .expect("inline EPSK configuration must parse");
        let mut new = previous.clone();
        new.server[0]
            .client_identity
            .as_mut()
            .unwrap()
            .tls13_epsk
            .as_mut()
            .unwrap()
            .inline_definition
            .as_mut()
            .unwrap()
            .cleartext_symmetric_key =
            Some(tacacsrs_secrets::SecretBytes::new(b"fedcba9876543210".to_vec()));

        let delta = ConfigDelta::diff(Some(&previous), &new);

        assert_eq!(delta.modified_servers, vec!["epsk"]);
    }

    #[tokio::test]
    async fn watch_stream_emits_subsequent_updates_only() {
        let initial = Arc::new(sample_config("192.0.2.1"));
        let (tx, rx) = watch::channel(Some(Arc::clone(&initial)));
        let mut stream = watch_to_change_stream(rx);

        // The initial value is the baseline, not a change.
        assert!(tokio::time::timeout(Duration::from_millis(25), stream.next())
            .await
            .is_err());

        let mut updated = sample_config("192.0.2.1");
        updated.server[0].timeout = 7;
        let updated_arc = Arc::new(updated);
        tx.send(Some(Arc::clone(&updated_arc)))
            .expect("send update");

        let ConfigChangeEvent::Changed(change) =
            stream.next().await.expect("stream must provide a change")
        else {
            panic!("expected a changed event");
        };
        assert_eq!(change.delta.modified_servers, vec!["primary"]);
        assert_eq!(change.config.server[0].timeout, 7);
    }

    #[tokio::test]
    async fn watch_stream_keeps_update_sent_before_first_poll() {
        let initial = Arc::new(sample_config("192.0.2.1"));
        let (tx, rx) = watch::channel(Some(Arc::clone(&initial)));
        let mut stream = watch_to_change_stream(rx);

        let mut updated = sample_config("192.0.2.1");
        updated.server[0].timeout = 9;
        tx.send(Some(Arc::new(updated))).expect("send update");

        let ConfigChangeEvent::Changed(change) = stream
            .next()
            .await
            .expect("stream must provide the first update")
        else {
            panic!("expected a changed event");
        };
        assert_eq!(change.delta.modified_servers, vec!["primary"]);
        assert_eq!(change.config.server[0].timeout, 9);
    }
}
