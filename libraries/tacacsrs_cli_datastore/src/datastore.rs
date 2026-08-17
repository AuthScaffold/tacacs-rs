use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tacacsrs_config::TacacsPlus;
use tacacsrs_datastore::{
    ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigChangeStream, ConfigDatastore,
    ConfigDelta, DatastoreRuntimePolicy, InitialLoadPolicy,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::builder::tacacs_plus_from_cli_input;
use crate::model::CliDatastoreInput;

/// File-backed datastore for CLI-supplied TACACS+ configuration inputs.
///
/// The datastore rebuilds the effective [`TacacsPlus`] snapshot after each
/// relevant file event. It publishes a successful rebuild to subscribers. If
/// a reload fails, it logs the error and keeps the active configuration.
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
}

#[async_trait]
impl ConfigDatastore for CliFileDatastore {
    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        let change_notifications = if self.input.watched_paths().is_empty() {
            ChangeNotificationMode::None
        } else {
            ChangeNotificationMode::Continuous
        };

        DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, change_notifications)
    }

    fn validation_options(&self) -> tacacsrs_config::ValidationOptions {
        self.input.validation_options()
    }

    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        tacacs_plus_from_cli_input(&self.input)
    }

    async fn subscribe(&self) -> anyhow::Result<ConfigChangeStream> {
        let watched_paths = self.input.watched_paths();
        if watched_paths.is_empty() {
            return Ok(Box::pin(tokio_stream::empty()));
        }

        let initial = self.load().await.ok().map(Arc::new);
        let (change_tx, change_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let watch_dirs = watch_directories(&watched_paths);
        let mut watcher = RecommendedWatcher::new(
            move |event| {
                if event_tx.blocking_send(event).is_err() {
                    log::debug!("CLI file datastore subscriber dropped; stopping watcher callback");
                }
            },
            Config::default(),
        )
        .context("create CLI file datastore watcher")?;

        for dir in &watch_dirs {
            watcher
                .watch(dir, RecursiveMode::NonRecursive)
                .with_context(|| format!("watch CLI datastore directory {}", dir.display()))?;
        }

        let datastore = self.clone();
        tokio::spawn(async move {
            let _watcher = watcher;
            let mut previous = initial;
            while let Some(event) = event_rx.recv().await {
                match event {
                    Ok(event) if event_touches_watched_path(&event, &watched_paths) => {
                        tokio::time::sleep(datastore.input.debounce).await;
                        while let Ok(Ok(_)) = event_rx.try_recv() {}
                        match datastore.load().await {
                            Ok(snapshot) => {
                                let snapshot = Arc::new(snapshot);
                                let change = ConfigChange {
                                    delta: ConfigDelta::diff(previous.as_deref(), &snapshot),
                                    config: Arc::clone(&snapshot),
                                };
                                previous = Some(snapshot);
                                if change_tx
                                    .send(ConfigChangeEvent::Changed(change))
                                    .await
                                    .is_err()
                                {
                                    log::debug!("CLI file datastore subscriber dropped; stopping");
                                    break;
                                }
                            }
                            Err(err) => {
                                log::error!(
                                    "CLI file datastore reload failed; keeping previous configuration: {err:#}"
                                );
                                if change_tx
                                    .send(ConfigChangeEvent::CandidateRejected)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        log::warn!("CLI file datastore watch event failed: {err:#}");
                    }
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(change_rx)))
    }

    fn label(&self) -> &'static str {
        self.input.label
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

    use futures_core::Stream;
    use tacacsrs_datastore::ConfigDatastore;
    use tokio::time::{timeout, Duration};

    use super::*;
    use crate::model::{
        CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs, CliServerInput,
    };

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

    fn sample_key_der() -> Vec<u8> {
        fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("tacacsrs_networking")
                .join("examples")
                .join("samples")
                .join("client.key.der"),
        )
        .expect("sample DER key exists")
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

    async fn next_change<S>(stream: &mut S) -> tacacsrs_datastore::ConfigChange
    where
        S: Stream<Item = tacacsrs_datastore::ConfigChangeEvent> + Unpin,
    {
        let event = timeout(Duration::from_secs(5), futures_util::StreamExt::next(stream))
            .await
            .expect("change must arrive")
            .expect("stream must yield a change");
        let tacacsrs_datastore::ConfigChangeEvent::Changed(change) = event else {
            panic!("expected changed event");
        };
        change
    }

    #[tokio::test]
    async fn subscribe_emits_change_after_config_file_update() {
        let path = temp_config(&config("192.0.2.10"));
        let input =
            CliDatastoreInput::new(CliConfigSource::YangFile { path: path.clone() }, "file")
                .with_debounce(Duration::from_millis(50));
        let datastore = CliFileDatastore::new(input);
        let mut stream = datastore
            .subscribe()
            .await
            .expect("subscription must succeed");

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
            .subscribe()
            .await
            .expect("subscription must succeed");

        fs::write(&path, "not valid JSON").expect("configuration file must update");

        let event = timeout(Duration::from_secs(5), futures_util::StreamExt::next(&mut stream))
            .await
            .expect("rejection must arrive")
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
        let cert_path = temp_file("cert", b"cert-a");
        let key_path = temp_file("key", &sample_key_der());
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
            .subscribe()
            .await
            .expect("subscription must succeed");

        fs::write(&cert_path, b"cert-b").expect("certificate file must update");

        let change = next_change(&mut stream).await;
        fs::remove_file(cert_path).ok();
        fs::remove_file(key_path).ok();

        assert_eq!(change.delta.modified_servers, vec!["server-0".to_owned()]);
    }
}
