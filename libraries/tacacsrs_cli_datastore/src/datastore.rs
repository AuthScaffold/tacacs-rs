use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tacacsrs_config::TacacsPlus;
use tacacsrs_datastore::{watch_to_change_stream, ConfigChangeStream, ConfigDatastore};
use tokio::sync::{mpsc, watch};

use crate::builder::tacacs_plus_from_cli_input;
use crate::model::CliDatastoreInput;

/// File-backed datastore for CLI-supplied TACACS+ configuration inputs.
///
/// The datastore rebuilds the effective [`TacacsPlus`] snapshot from the
/// original CLI/file inputs on every relevant filesystem event. A successful
/// rebuild is published to subscribers; failed reloads are logged and the
/// previous active configuration remains in effect.
#[derive(Debug, Clone)]
pub struct CliFileDatastore {
    input: CliDatastoreInput,
}

impl CliFileDatastore {
    /// Create a new file-backed datastore from parsed CLI inputs.
    #[must_use]
    pub fn new(input: CliDatastoreInput) -> Self {
        Self { input }
    }

    /// Parsed input model used to build each configuration snapshot.
    #[must_use]
    pub fn input(&self) -> &CliDatastoreInput {
        &self.input
    }
}

#[async_trait]
impl ConfigDatastore for CliFileDatastore {
    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        tacacs_plus_from_cli_input(&self.input)
    }

    async fn subscribe(&self) -> anyhow::Result<ConfigChangeStream> {
        let watched_paths = self.input.watched_paths();
        if watched_paths.is_empty() {
            return Ok(Box::pin(tokio_stream::empty()));
        }

        let initial = self.load().await.ok().map(Arc::new);
        let (snapshot_tx, snapshot_rx) = watch::channel(initial);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let watch_dirs = watch_directories(&watched_paths);
        let mut watcher = RecommendedWatcher::new(
            move |event| {
                if event_tx.blocking_send(event).is_err() {
                    log::debug!("CLI file datastore subscriber dropped; exiting watcher callback");
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
            while let Some(event) = event_rx.recv().await {
                match event {
                    Ok(event) if event_touches_watched_path(&event, &watched_paths) => {
                        tokio::time::sleep(datastore.input.debounce).await;
                        while let Ok(Ok(_)) = event_rx.try_recv() {}
                        match datastore.load().await {
                            Ok(snapshot) => {
                                if snapshot_tx.send(Some(Arc::new(snapshot))).is_err() {
                                    log::debug!("CLI file datastore subscriber dropped; exiting");
                                    break;
                                }
                            }
                            Err(err) => {
                                log::error!(
                                    "CLI file datastore reload failed; keeping previous configuration: {err:#}"
                                );
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

        Ok(watch_to_change_stream(snapshot_rx))
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

    // We watch the parent directory (not the file), so `notify` may report a
    // sibling path that is not byte-identical to `watched_path` (for example a
    // non-canonicalized form after an atomic rename). Matching on file name plus
    // parent covers those cases without watching unrelated files.
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
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cli-file-datastore-{unique}.json"));
        fs::write(&path, contents).expect("temp config should be written");
        path
    }

    fn temp_file(prefix: &str, contents: &[u8]) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cli-file-datastore-{prefix}-{unique}"));
        fs::write(&path, contents).expect("temp file should be written");
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
        S: Stream<Item = tacacsrs_datastore::ConfigChange> + Unpin,
    {
        timeout(Duration::from_secs(5), futures_util::StreamExt::next(stream))
            .await
            .expect("change should arrive")
            .expect("stream should yield change")
    }

    #[tokio::test]
    async fn subscribe_emits_change_after_config_file_update() {
        let path = temp_config(&config("192.0.2.10"));
        let input =
            CliDatastoreInput::new(CliConfigSource::YangFile { path: path.clone() }, "file")
                .with_debounce(Duration::from_millis(50));
        let datastore = CliFileDatastore::new(input);
        let mut stream = datastore.subscribe().await.expect("subscribe should work");

        fs::write(&path, config("192.0.2.11")).expect("config should update");

        let change = next_change(&mut stream).await;
        fs::remove_file(path).ok();

        assert_eq!(change.config.server[0].address, "192.0.2.11");
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
        let mut stream = datastore.subscribe().await.expect("subscribe should work");

        fs::write(&cert_path, b"cert-b").expect("certificate should update");

        let change = next_change(&mut stream).await;
        fs::remove_file(cert_path).ok();
        fs::remove_file(key_path).ok();

        assert_eq!(change.delta.modified_servers, vec!["server-0".to_owned()]);
    }
}
