use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use notify::event::ModifyKind;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::TacacsPlus;
use crate::source::{
    ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigDatastore, ConfigDelta,
    ConfigObservation, DatastoreRuntimePolicy, InitialLoadPolicy,
};
use super::builder::tacacs_plus_from_cli_input;
use super::model::CliDatastoreInput;

/// File-backed datastore for CLI-supplied TACACS+ configuration inputs.
///
/// The datastore rebuilds the effective [`TacacsPlus`] snapshot after each
/// relevant file event. It publishes a successful rebuild to subscribers. If
/// a reload fails, it logs the error and keeps the active configuration.
/// Subscriptions install observation before publishing an initial snapshot.
/// The observation owns its watcher and pending read. Reads use Tokio's blocking
/// pool, so they do not block the async runtime. A started blocking read can
/// finish after session drop, but it cannot publish into a dropped session.
#[derive(Debug, Clone)]
pub struct CliFileDatastore {
    input: CliDatastoreInput,
}

impl CliFileDatastore {
    /// Creates a file-backed datastore from parsed CLI inputs.
    #[must_use]
    pub fn new(input: CliDatastoreInput) -> Self {
        Self { input }
    }

    /// Returns the parsed input model for each configuration snapshot.
    #[must_use]
    pub fn input(&self) -> &CliDatastoreInput {
        &self.input
    }

    async fn open_observation(&self) -> anyhow::Result<FileObservation> {
        let mut input = self.input.clone();
        input.capture_paths().await?;
        let watched_paths = input.watched_paths();
        let (events, invalidations) = watch::channel(None::<Arc<notify::Error>>);
        let watcher = if watched_paths.is_empty() {
            None
        } else {
            let watch_dirs = watch_directories(&watched_paths);
            let directories = watch_dirs.clone();
            let mut watcher = RecommendedWatcher::new(
                move |event: notify::Result<Event>| {
                    let error = match event {
                        Ok(event)
                            if event.paths.iter().any(|path| directories.contains(path))
                                && matches!(
                                    event.kind,
                                    EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
                                ) =>
                        {
                            Some(Arc::new(notify::Error::generic(
                                "Configuration directory was removed or renamed",
                            )))
                        }
                        Ok(event) if event_touches_watched_path(&event, &watched_paths) => None,
                        Ok(_) => return,
                        Err(error) => Some(Arc::new(error)),
                    };
                    events.send_modify(|current| {
                        if current.is_none() {
                            *current = error;
                        }
                    });
                },
                Config::default(),
            )
            .context("create configuration watcher")?;
            for directory in watch_dirs {
                watcher
                    .watch(&directory, RecursiveMode::NonRecursive)
                    .with_context(|| {
                        format!("watch configuration directory {}", directory.display())
                    })?;
            }
            Some(watcher)
        };
        Ok(FileObservation {
            watcher,
            input,
            invalidations,
            previous: None,
            pending: true,
            debounce_until: None,
            read: None,
        })
    }
}

#[async_trait]
impl ConfigDatastore for CliFileDatastore {
    async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
        Ok(Box::new(self.open_observation().await?))
    }

    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        let change_notifications = if self.input.watched_paths().is_empty() {
            ChangeNotificationMode::None
        } else {
            ChangeNotificationMode::Continuous
        };

        DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, change_notifications)
    }

    fn validation_options(&self) -> crate::ValidationOptions {
        self.input.validation_options()
    }

    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        tacacs_plus_from_cli_input(&self.input)
    }

    fn label(&self) -> &'static str {
        self.input.label
    }
}

struct FileObservation {
    watcher: Option<RecommendedWatcher>,
    input: CliDatastoreInput,
    invalidations: watch::Receiver<Option<Arc<notify::Error>>>,
    previous: Option<Arc<TacacsPlus>>,
    pending: bool,
    debounce_until: Option<Instant>,
    read: Option<JoinHandle<anyhow::Result<TacacsPlus>>>,
}

impl Drop for FileObservation {
    fn drop(&mut self) {
        if let Some(read) = &self.read {
            read.abort();
        }
    }
}

#[async_trait]
impl ConfigObservation for FileObservation {
    async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
        if !self.pending {
            if self.watcher.is_none() {
                return Ok(None);
            }
            self.invalidations
                .changed()
                .await
                .context("configuration watcher stopped")?;
            self.pending = true;
            self.debounce_until = Some(Instant::now() + self.input.debounce);
        }
        if self.read.is_none() {
            if let Some(deadline) = self.debounce_until {
                tokio::time::sleep_until(deadline).await;
            }
            let error = self.invalidations.borrow_and_update().clone();
            if let Some(error) = error {
                anyhow::bail!("Configuration observation failed: {error}");
            }
            let input = self.input.clone();
            self.read =
                Some(tokio::task::spawn_blocking(move || tacacs_plus_from_cli_input(&input)));
        }
        let read = self
            .read
            .as_mut()
            .context("configuration read is missing")?;
        let candidate = read.await;
        self.read = None;
        self.pending = false;
        self.debounce_until = None;
        let candidate = candidate.context("configuration reader stopped")?;
        Ok(Some(if let Ok(snapshot) = candidate {
            let snapshot = Arc::new(snapshot);
            let delta = ConfigDelta::diff(self.previous.as_deref(), &snapshot);
            self.previous = Some(snapshot.clone());
            ConfigChangeEvent::Changed(ConfigChange {
                config: snapshot,
                delta,
            })
        } else {
            log::warn!("Configuration candidate was rejected");
            ConfigChangeEvent::CandidateRejected
        }))
    }
}

fn watch_directories(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = BTreeSet::new();
    for path in paths {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        dirs.insert(dir.to_path_buf());
    }
    dirs.into_iter().collect()
}

fn event_touches_watched_path(event: &Event, watched_paths: &[PathBuf]) -> bool {
    if event.need_rescan() {
        return true;
    }
    if matches!(event.kind, EventKind::Access(_)) {
        return false;
    }
    if event.paths.is_empty() {
        return true;
    }
    event.paths.iter().any(|event_path| {
        watched_paths
            .iter()
            .any(|watched_path| paths_match(event_path, watched_path))
    })
}

fn paths_match(event_path: &Path, watched_path: &Path) -> bool {
    if event_path == watched_path {
        return true;
    }

    // We watch the parent directory, not the file. After an atomic rename,
    // `notify` can report a noncanonical form of the same path. Compare the
    // parent and file name to match it without watching unrelated files.
    event_path.file_name() == watched_path.file_name()
        && event_path.parent() == watched_path.parent()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::time::{timeout, Duration};

    use crate::source::ConfigDatastore;
    use super::super::model::{
        CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs, CliServerInput,
    };
    use super::*;

    #[test]
    fn observation_filters_access_but_reconciles_rescan_events() {
        use notify::event::{AccessKind, Flag, ModifyKind};
        use notify::EventKind;

        let path = PathBuf::from("/tmp/configuration.json");
        let access = Event::new(EventKind::Access(AccessKind::Read)).add_path(path.clone());
        assert!(!event_touches_watched_path(&access, std::slice::from_ref(&path)));
        let modified = Event::new(EventKind::Modify(ModifyKind::Any)).add_path(path.clone());
        assert!(event_touches_watched_path(&modified, std::slice::from_ref(&path)));
        let rescan = Event::new(EventKind::Other).set_flag(Flag::Rescan);
        assert!(event_touches_watched_path(&rescan, &[path]));
    }

    fn temp_config(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cli-file-datastore-{unique}.json"));
        fs::write(&path, contents).expect("temporary configuration file must be written");
        path
    }

    fn temp_file(prefix: &str, contents: &[u8]) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cli-file-datastore-{prefix}-{unique}"));
        fs::write(&path, contents).expect("temporary file must be written");
        path
    }

    fn sample_credential(file_name: &str) -> Vec<u8> {
        fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("lde/containers/config/certificates")
                .join(file_name),
        )
        .expect("sample credential exists")
    }

    fn config(address: &str) -> String {
        format!(
            r#"{{
                "ietf-system-tacacs-plus:tacacs-plus": {{
                    "server": [{{
                        "name": "primary",
                        "server-type": "accounting",
                        "address": "{address}",
                        "port": 49,
                        "shared-secret": "secret1"
                    }}]
                }}
            }}"#
        )
    }

    async fn next_change(stream: &mut Box<dyn ConfigObservation>) -> crate::source::ConfigChange {
        let event = timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("change must arrive")
            .expect("observation must succeed")
            .expect("stream must yield a change");
        let crate::source::ConfigChangeEvent::Changed(change) = event else {
            panic!("expected changed event");
        };
        change
    }

    #[tokio::test]
    async fn normalized_input_uses_shared_source_and_preparation_contract() {
        use tacacsrs_networking::TacacsClient;

        use crate::input::{CliPskInputs, PskKeyExchangeMode, PskKeyMaterial};
        use crate::prepare::PrepareOptions;
        use crate::source::StaticDatastore;

        for security in [
            CliSecurityInputs {
                shared_secret: Some("test-secret".to_owned()),
                ..Default::default()
            },
            CliSecurityInputs {
                use_tls: true,
                psk: Some(CliPskInputs {
                    identity: "client".to_owned(),
                    key: PskKeyMaterial::Raw(b"test-psk-with-enough-bytes".to_vec()),
                    exchange: PskKeyExchangeMode::PskOnly,
                    groups: Vec::new(),
                }),
                ..Default::default()
            },
        ] {
            let datastore = CliFileDatastore::new(CliDatastoreInput::new(
                CliConfigSource::Inline {
                    servers: vec![
                        CliServerInput::new("first", "192.0.2.10:49")
                            .with_timeout_seconds(9)
                            .with_single_connection(false),
                        CliServerInput::new("second", "[2001:db8::2]:49").with_timeout_seconds(7),
                    ],
                    security: CliSecurity::from_cli_inputs(security),
                },
                "cli",
            ));
            let snapshot = datastore.load().await.unwrap();
            let static_source = StaticDatastore::new(snapshot.clone());
            for source in [&datastore as &dyn ConfigDatastore, &static_source] {
                let loaded = source.load().await.unwrap();
                assert_eq!(loaded, snapshot);
                assert_eq!(
                    loaded
                        .server
                        .iter()
                        .map(|server| server.name.as_str())
                        .collect::<Vec<_>>(),
                    ["first", "second"]
                );
                assert_eq!(
                    loaded
                        .server
                        .iter()
                        .map(|server| server.timeout)
                        .collect::<Vec<_>>(),
                    [9, 7]
                );
                let endpoint =
                    crate::prepare::prepare_endpoint(&loaded.server[0], PrepareOptions::default())
                        .unwrap();
                assert_eq!(endpoint.address(), "192.0.2.10:49");
                assert!(!endpoint.single_connection());
                assert_eq!(endpoint.connection_timeout(), Some(Duration::from_secs(9)));
                TacacsClient::connect_prepared(endpoint).await.unwrap();
                assert_eq!(loaded, snapshot);
                let mut observation = source.observe().await.unwrap();
                next_change(&mut observation).await;
                assert!(observation.next().await.unwrap().is_none());
            }
        }
    }

    #[tokio::test]
    async fn subscription_recovers_change_between_load_and_watch() {
        let path = temp_config(&config("192.0.2.10"));
        let datastore = CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::YangFile { path: path.clone() },
            "file",
        ));
        assert_eq!(datastore.load().await.unwrap().server[0].address, "192.0.2.10");
        fs::write(&path, config("192.0.2.11")).unwrap();

        let mut stream = datastore.observe().await.unwrap();
        let change = next_change(&mut stream).await;
        assert_eq!(change.config.server[0].address, "192.0.2.11");
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn owned_observation_reads_after_watch_and_releases_watcher_on_drop() {
        let path = temp_config(&config("192.0.2.10"));
        let datastore = CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::YangFile { path: path.clone() },
            "file",
        ));
        let mut observation = datastore.open_observation().await.unwrap();
        let mut lifetime = observation.invalidations.clone();
        fs::write(&path, config("192.0.2.11")).unwrap();
        let Some(ConfigChangeEvent::Changed(change)) = observation.next().await.unwrap() else {
            panic!("observation must yield the current baseline");
        };
        assert_eq!(change.config.server[0].address, "192.0.2.11");
        drop(observation);
        timeout(Duration::from_secs(1), async { while lifetime.changed().await.is_ok() {} })
            .await
            .expect("dropping the observation must release the native watcher callback");
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn cancelled_debounce_coalesces_bursts_and_preserves_rejected_baseline() {
        let path = temp_config(&config("192.0.2.10"));
        let datastore = CliFileDatastore::new(
            CliDatastoreInput::new(CliConfigSource::YangFile { path: path.clone() }, "file")
                .with_debounce(Duration::from_millis(20)),
        );
        let mut observation = datastore.open_observation().await.unwrap();
        observation.next().await.unwrap();
        let (events, invalidations) = watch::channel(None);
        observation.invalidations = invalidations;
        for _ in 0..10_000 {
            events.send_replace(None);
        }
        {
            let next = observation.next();
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
        }
        fs::write(&path, "invalid JSON").unwrap();
        assert!(matches!(
            observation.next().await.unwrap(),
            Some(ConfigChangeEvent::CandidateRejected)
        ));
        fs::write(&path, config("192.0.2.12")).unwrap();
        events.send_replace(None);
        let Some(ConfigChangeEvent::Changed(change)) = observation.next().await.unwrap() else {
            panic!("valid replacement must recover");
        };
        assert_eq!(change.config.server[0].address, "192.0.2.12");
        assert_eq!(change.delta.modified_servers, ["primary"]);
        assert_eq!(change.delta.added_servers.len(), 0);
        drop(observation);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn cancelled_pending_read_is_retained_and_concurrent_invalidation_is_not_lost() {
        let path = temp_config(&config("192.0.2.10"));
        let datastore = CliFileDatastore::new(
            CliDatastoreInput::new(CliConfigSource::YangFile { path: path.clone() }, "file")
                .with_debounce(Duration::ZERO),
        );
        let mut observation = datastore.open_observation().await.unwrap();
        let first = tacacs_plus_from_cli_input(&observation.input).unwrap();
        let (release, ready) = tokio::sync::oneshot::channel();
        observation.read = Some(tokio::spawn(async move {
            ready.await.unwrap();
            Ok(first)
        }));
        let (events, invalidations) = watch::channel(None);
        observation.invalidations = invalidations;
        {
            let next = observation.next();
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
        }
        fs::write(&path, config("192.0.2.11")).unwrap();
        events.send_replace(None);
        release.send(()).unwrap();
        let Some(ConfigChangeEvent::Changed(first)) = observation.next().await.unwrap() else {
            panic!("cancelled read must remain owned");
        };
        assert_eq!(first.config.server[0].address, "192.0.2.10");
        let Some(ConfigChangeEvent::Changed(latest)) =
            timeout(Duration::from_secs(1), observation.next())
                .await
                .unwrap()
                .unwrap()
        else {
            panic!("invalidation during the read must trigger reconciliation");
        };
        assert_eq!(latest.config.server[0].address, "192.0.2.11");
        drop(observation);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn observation_reads_the_same_captured_directory_that_it_watches() {
        let seed = temp_config("");
        let original = seed.with_extension("original");
        let replacement = seed.with_extension("replacement");
        let alias = seed.with_extension("alias");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(original.join("config.json"), config("192.0.2.10")).unwrap();
        fs::write(replacement.join("config.json"), config("192.0.2.11")).unwrap();
        std::os::unix::fs::symlink(&original, &alias).unwrap();
        let datastore = CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::YangFile {
                path: alias.join("config.json"),
            },
            "file",
        ));
        let mut observation = datastore.observe().await.unwrap();
        fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        let Some(ConfigChangeEvent::Changed(change)) = observation.next().await.unwrap() else {
            panic!("observation must retain its watched directory");
        };
        assert_eq!(change.config.server[0].address, "192.0.2.10");
        drop(observation);
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(original).unwrap();
        fs::remove_dir_all(replacement).unwrap();
        fs::remove_file(seed).unwrap();
    }

    #[tokio::test]
    async fn watched_directory_loss_is_an_observation_error() {
        let directory = temp_config("").with_extension("directory");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("config.json");
        fs::write(&path, config("192.0.2.10")).unwrap();
        let datastore = CliFileDatastore::new(
            CliDatastoreInput::new(CliConfigSource::YangFile { path: path.clone() }, "file")
                .with_debounce(Duration::ZERO),
        );
        let mut observation = datastore.observe().await.unwrap();
        observation.next().await.unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(&directory).unwrap();
        timeout(Duration::from_secs(1), async { while observation.next().await.is_ok() {} })
            .await
            .expect("watch loss must be reported");
        fs::remove_file(directory.with_extension("json")).unwrap();
    }

    #[tokio::test]
    async fn subscribe_emits_change_after_config_file_update() {
        let path = temp_config(&config("192.0.2.10"));
        let input =
            CliDatastoreInput::new(CliConfigSource::YangFile { path: path.clone() }, "file")
                .with_debounce(Duration::from_millis(50));
        let datastore = CliFileDatastore::new(input);
        let mut stream = datastore
            .observe()
            .await
            .expect("subscription must succeed");
        assert_eq!(next_change(&mut stream).await.config.server[0].address, "192.0.2.10");

        fs::write(&path, config("192.0.2.11")).expect("configuration file must update");

        let change = next_change(&mut stream).await;
        fs::remove_file(path).ok();

        assert_eq!(change.config.server[0].address, "192.0.2.11");
    }

    #[tokio::test]
    async fn subscribe_reports_rejected_candidate_after_invalid_file_update() {
        let path = temp_config(&config("192.0.2.10"));
        let input =
            CliDatastoreInput::new(CliConfigSource::YangFile { path: path.clone() }, "file")
                .with_debounce(Duration::from_millis(50));
        let datastore = CliFileDatastore::new(input);
        let mut stream = datastore
            .observe()
            .await
            .expect("subscription must succeed");
        next_change(&mut stream).await;

        fs::write(&path, "not valid JSON").expect("configuration file must update");

        let event = timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("rejection must arrive")
            .expect("observation must succeed")
            .expect("stream must yield a rejection");
        fs::remove_file(path).ok();

        assert!(matches!(event, ConfigChangeEvent::CandidateRejected));
    }

    #[test]
    fn runtime_policy_is_continuous_only_when_files_are_watched() {
        let inline = CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::Inline {
                servers: vec![CliServerInput::new("server-0", "192.0.2.10:49")],
                security: CliSecurity::from_cli_inputs(CliSecurityInputs::default()),
            },
            "cli",
        ));
        assert_eq!(
            inline.runtime_policy(),
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None,)
        );

        let path = temp_config(&config("192.0.2.10"));
        let file = CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::YangFile { path: path.clone() },
            "file",
        ));
        assert_eq!(
            file.runtime_policy(),
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::FailFast,
                ChangeNotificationMode::Continuous,
            )
        );
        fs::remove_file(path).ok();
    }

    #[tokio::test]
    async fn subscribe_emits_change_after_certificate_file_update() {
        let cert_path = temp_file("cert", &sample_credential("client.crt"));
        let key_path = temp_file("key", &sample_credential("client.key.der"));
        let input = CliDatastoreInput::new(
            CliConfigSource::Inline {
                servers: vec![CliServerInput::new("server-0", "192.0.2.10:49")],
                security: CliSecurity::from_cli_inputs(CliSecurityInputs {
                    use_tls: true,
                    client_certificate: Some(cert_path.clone()),
                    client_key: Some(key_path.clone()),
                    ..Default::default()
                }),
            },
            "cli",
        )
        .with_debounce(Duration::from_millis(50));
        let datastore = CliFileDatastore::new(input);
        let mut stream = datastore
            .observe()
            .await
            .expect("subscription must succeed");
        next_change(&mut stream).await;

        fs::write(&cert_path, sample_credential("server.crt"))
            .expect("certificate file must update");

        let change = next_change(&mut stream).await;
        fs::remove_file(cert_path).ok();
        fs::remove_file(key_path).ok();

        assert_eq!(change.delta.modified_servers, vec!["server-0".to_owned()]);
    }
}
