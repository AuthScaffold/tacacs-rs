#![doc = include_str!("../README.md")]
#![allow(clippy::doc_markdown, clippy::ignored_unit_patterns)]

pub mod mapping;
mod provider;
pub mod store;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_config::TacacsPlus;
use tacacsrs_datastore::{
    ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigChangeStream, ConfigDatastore,
    ConfigDelta, DatastoreRuntimePolicy, InitialLoadPolicy,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub use mapping::{map_sonic_tables_to_tacacs_plus, sonic_server_name, SonicHash, SonicTacacsTables};
pub use provider::{
    SonicCredentialInitializationError, SonicCredentialPolicy, SonicCredentialResolver,
    SonicCredentialRoots,
};
pub use store::{
    read_tacacs_tables, spawn_change_notifier, SonicConnection, DEFAULT_REDIS_URL,
    TACPLUS_FORWARDER_TABLE, TACPLUS_GLOBAL_TABLE, TACPLUS_SERVER_TABLE, TACPLUS_SERVER_TLS_TABLE,
};

/// SONiC ConfigDB-backed [`ConfigDatastore`] implementation.
///
/// Reads the compatibility, TLS upstream, and forwarder TACACS+ tables from
/// CONFIG_DB and emits a
/// [`tacacsrs_datastore::ConfigChange`] every time a TACPLUS-prefixed key
/// changes (subject to the configured debounce window).
///
/// The datastore is intentionally constructed with a connection settings
/// struct rather than a live client: the actual Redis connection is opened
/// lazily inside [`load`](Self::load) / [`subscribe`](Self::subscribe) so the
/// daemon can survive a restart of the SONiC `database.service`.
pub struct SonicConfigDb {
    settings: SonicConnection,
}

impl SonicConfigDb {
    /// Create a new datastore with the supplied connection settings.
    #[must_use]
    pub fn new(settings: SonicConnection) -> Self {
        Self { settings }
    }

    /// Connection settings used to open Redis connections.
    #[must_use]
    pub fn settings(&self) -> &SonicConnection {
        &self.settings
    }
}

#[async_trait]
impl ConfigDatastore for SonicConfigDb {
    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        DatastoreRuntimePolicy::new(
            InitialLoadPolicy::RetryUntilAvailable,
            ChangeNotificationMode::Continuous,
        )
    }

    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        let mut conn = self
            .settings
            .connect()
            .await
            .context("connect to SONiC ConfigDB for initial load")?;
        let snapshot = read_tacacs_tables(&mut conn)
            .await
            .context("read complete TACACS+ tables from ConfigDB")?;
        map_sonic_tables_to_tacacs_plus(&snapshot)
            .context("map SONiC ConfigDB tables to YANG TACACS+ configuration")
    }

    async fn subscribe(&self) -> anyhow::Result<ConfigChangeStream> {
        let settings = self.settings.clone();
        let initial = self.load().await.ok().map(Arc::new);
        let (tx, rx) = mpsc::channel(8);
        let mut signal = spawn_change_notifier(settings.clone())
            .await
            .context("subscribe to SONiC ConfigDB keyspace notifications")?;

        tokio::spawn(async move {
            let mut previous = initial;
            while signal.recv().await.is_some() {
                match reload_with_retry(&settings).await {
                    Ok(snapshot) => {
                        let snapshot = Arc::new(snapshot);
                        let change = ConfigChange {
                            delta: ConfigDelta::diff(previous.as_deref(), &snapshot),
                            config: Arc::clone(&snapshot),
                        };
                        previous = Some(snapshot);
                        if tx.send(ConfigChangeEvent::Changed(change)).await.is_err() {
                            log::debug!("SONiC datastore subscriber dropped; exiting");
                            break;
                        }
                    }
                    Err(err) => {
                        log::error!(
                            "SONiC ConfigDB reload failed; keeping previous configuration: {err:#}"
                        );
                        if tx.send(ConfigChangeEvent::CandidateRejected).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    fn label(&self) -> &'static str {
        "sonic-configdb"
    }
}

/// Reconnect-and-reload helper used by the change subscriber.
///
/// SONiC's `database.service` may be restarted independently of
/// `tacacsrs-agentd`. To survive these blips we attempt a small number of
/// reconnect retries before giving up on a particular notification.
async fn reload_with_retry(settings: &SonicConnection) -> anyhow::Result<TacacsPlus> {
    const MAX_ATTEMPTS: usize = 3;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match try_reload(settings).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(err) => {
                log::warn!(
                    "SONiC ConfigDB reload attempt {attempt}/{MAX_ATTEMPTS} failed: {err:#}"
                );
                last_err = Some(err);
                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("SONiC ConfigDB reload exhausted retries")))
}

async fn try_reload(settings: &SonicConnection) -> anyhow::Result<TacacsPlus> {
    let mut conn = settings.connect().await?;
    let snapshot = read_tacacs_tables(&mut conn).await?;
    map_sonic_tables_to_tacacs_plus(&snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_policy_retries_and_maintains_continuous_notifications() {
        let datastore = SonicConfigDb::new(SonicConnection::default());

        assert_eq!(
            datastore.runtime_policy(),
            DatastoreRuntimePolicy::new(
                InitialLoadPolicy::RetryUntilAvailable,
                ChangeNotificationMode::Continuous,
            )
        );
    }
}
