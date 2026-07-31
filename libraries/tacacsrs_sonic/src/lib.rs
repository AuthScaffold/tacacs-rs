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

pub use mapping::{
    SonicForwarderSettings, SonicHash, SonicTacacsTables, map_sonic_tables_to_tacacs_plus,
    sonic_server_name,
};
pub use provider::{
    SonicCredentialInitializationError, SonicCredentialPolicy, SonicCredentialResolver,
    SonicCredentialRoots,
};
pub use store::{
    DEFAULT_REDIS_URL, SonicConnection, TACPLUS_FORWARDER_TABLE, TACPLUS_GLOBAL_TABLE,
    TACPLUS_SERVER_TABLE, TACPLUS_SERVER_TLS_TABLE, read_tacacs_tables, spawn_change_notifier,
    spawn_credential_change_notifier,
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
    bound_forwarder: Option<SonicForwarderSettings>,
}

impl SonicConfigDb {
    /// Create a new datastore with the supplied connection settings.
    #[must_use]
    pub fn new(settings: SonicConnection) -> Self {
        Self {
            settings,
            bound_forwarder: None,
        }
    }

    /// Creates a datastore that compares later forwarder snapshots with the
    /// settings already used to bind service listeners.
    #[must_use]
    pub fn with_bound_forwarder(
        settings: SonicConnection,
        bound_forwarder: SonicForwarderSettings,
    ) -> Self {
        Self {
            settings,
            bound_forwarder: Some(bound_forwarder),
        }
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
        let bound_forwarder = self.bound_forwarder;
        let initial = self.load().await.ok().map(Arc::new);
        let (tx, rx) = mpsc::channel(8);
        let mut signal = spawn_change_notifier(settings.clone())
            .await
            .context("subscribe to SONiC ConfigDB keyspace notifications")?;
        let mut credential_signal = match settings.credential_watch_root.clone() {
            Some(root) => Some(
                spawn_credential_change_notifier(root, settings.debounce)
                    .await
                    .context("subscribe to SONiC credential changes")?,
            ),
            None => None,
        };

        tokio::spawn(async move {
            let mut previous = initial;
            loop {
                let next_signal = match credential_signal.as_mut() {
                    Some(credential_signal) => {
                        tokio::select! {
                            signal = signal.recv() => signal,
                            signal = credential_signal.recv() => signal,
                        }
                    }
                    None => signal.recv().await,
                };
                if next_signal.is_none() {
                    break;
                }
                while signal.try_recv().is_ok() {}
                if let Some(credential_signal) = credential_signal.as_mut() {
                    while credential_signal.try_recv().is_ok() {}
                }
                match reload_with_retry(&settings).await {
                    Ok(candidate) => {
                        let restart_required = match bound_forwarder {
                            Some(bound) => candidate.forwarder != Some(bound),
                            None => false,
                        };
                        let snapshot = Arc::new(candidate.config);
                        let change = ConfigChange {
                            delta: ConfigDelta::diff(previous.as_deref(), &snapshot),
                            config: Arc::clone(&snapshot),
                        };
                        previous = Some(snapshot);
                        if tx.send(ConfigChangeEvent::Changed(change)).await.is_err() {
                            log::debug!("SONiC datastore subscriber dropped; exiting");
                            break;
                        }
                        if tx
                            .send(ConfigChangeEvent::RestartRequired {
                                required: restart_required,
                            })
                            .await
                            .is_err()
                        {
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
struct ReloadedCandidate {
    config: TacacsPlus,
    forwarder: Option<SonicForwarderSettings>,
}

async fn reload_with_retry(settings: &SonicConnection) -> anyhow::Result<ReloadedCandidate> {
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

async fn try_reload(settings: &SonicConnection) -> anyhow::Result<ReloadedCandidate> {
    let mut conn = settings.connect().await?;
    let snapshot = read_tacacs_tables(&mut conn).await?;
    let forwarder = SonicForwarderSettings::from_hash(&snapshot.forwarder)?;
    let config = map_sonic_tables_to_tacacs_plus(&snapshot)?;
    Ok(ReloadedCandidate { config, forwarder })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures_util::StreamExt;
    use redis::AsyncCommands;
    use tokio::time::timeout;

    use super::*;

    async fn next_event(events: &mut ConfigChangeStream, context: &str) -> ConfigChangeEvent {
        timeout(Duration::from_secs(5), events.next())
            .await
            .unwrap_or_else(|_| panic!("{context} timeout"))
            .unwrap_or_else(|| panic!("{context} missing"))
    }

    async fn seed_redis(connection: &mut redis::aio::MultiplexedConnection) {
        redis::cmd("FLUSHDB")
            .query_async::<()>(connection)
            .await
            .expect("flush test database");
        redis::cmd("CONFIG")
            .arg("SET")
            .arg("notify-keyspace-events")
            .arg("Kgh")
            .query_async::<()>(connection)
            .await
            .expect("enable keyspace notifications");
        connection
            .hset_multiple::<_, _, _, ()>(
                "TACPLUS_FORWARDER|global",
                &[
                    ("local_listen_address", "127.0.0.1"),
                    ("local_listen_port", "49"),
                ],
            )
            .await
            .expect("seed forwarder");
        connection
            .hset_multiple::<_, _, _, ()>(
                "TACPLUS_SERVER|192.0.2.10",
                &[("priority", "1"), ("passkey", "x")],
            )
            .await
            .expect("seed server");
        connection
            .hset_multiple::<_, _, _, ()>(
                "TACPLUS_SERVER_TLS|192.0.2.20",
                &[
                    ("priority", "3"),
                    ("psk_identity", "client"),
                    ("psk_secret_ref", "epsk-object"),
                ],
            )
            .await
            .expect("seed TLS server");
    }

    async fn set_field(
        connection: &mut redis::aio::MultiplexedConnection,
        key: &str,
        field: &str,
        value: &str,
    ) {
        connection
            .hset::<_, _, _, ()>(key, field, value)
            .await
            .expect("set Redis field");
    }

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

    #[tokio::test]
    async fn redis_forwarder_changes_report_restart_without_blocking_server_reload() {
        let Ok(url) = std::env::var("TACACSRS_SONIC_TEST_REDIS_URL") else {
            return;
        };
        let settings = SonicConnection {
            url,
            db_index: 15,
            debounce: Duration::from_millis(20),
            credential_watch_root: None,
        };
        let mut connection = settings.connect().await.expect("connect test Redis");
        seed_redis(&mut connection).await;

        let bound = settings
            .load_forwarder_settings()
            .await
            .expect("load bound forwarder");
        let datastore = SonicConfigDb::with_bound_forwarder(settings, bound);
        let initial = datastore.load().await.expect("initial complete snapshot");
        assert_eq!(initial.server.len(), 2);
        assert!(initial.server.iter().any(|server| {
            server
                .client_identity
                .as_ref()
                .and_then(|identity| identity.tls13_epsk.as_ref())
                .is_some()
        }));
        let mut events = datastore.subscribe().await.expect("subscribe");

        set_field(&mut connection, "TACPLUS_FORWARDER|global", "local_listen_port", "50").await;
        set_field(&mut connection, "TACPLUS_SERVER|192.0.2.10", "timeout", "6").await;
        set_field(&mut connection, "TACPLUS_SERVER_TLS|192.0.2.20", "timeout", "7").await;
        let changed = next_event(&mut events, "changed event").await;
        let ConfigChangeEvent::Changed(changed) = changed else {
            panic!("expected changed event");
        };
        assert_eq!(changed.config.server.len(), 2);
        assert_eq!(changed.config.server[0].address, "192.0.2.20");
        assert_eq!(changed.config.server[0].timeout, 7);
        assert_eq!(changed.config.server[1].name, sonic_server_name("192.0.2.10"));
        assert_eq!(changed.config.server[1].timeout, 6);
        assert!(changed
            .delta
            .modified_servers
            .contains(&sonic_server_name("192.0.2.10")));
        assert!(changed
            .delta
            .modified_servers
            .contains(&sonic_server_name("192.0.2.20")));
        assert!(matches!(
            next_event(&mut events, "restart event").await,
            ConfigChangeEvent::RestartRequired { required: true }
        ));

        connection
            .del::<_, ()>("TACPLUS_FORWARDER|global")
            .await
            .expect("delete forwarder");
        assert!(matches!(
            next_event(&mut events, "deletion change").await,
            ConfigChangeEvent::Changed(_)
        ));
        assert!(matches!(
            next_event(&mut events, "deletion restart").await,
            ConfigChangeEvent::RestartRequired { required: true }
        ));

        connection
            .hset_multiple::<_, _, _, ()>(
                "TACPLUS_FORWARDER|global",
                &[
                    ("local_listen_address", "127.0.0.1"),
                    ("local_listen_port", "49"),
                ],
            )
            .await
            .expect("restore forwarder");
        assert!(matches!(
            next_event(&mut events, "restore change").await,
            ConfigChangeEvent::Changed(_)
        ));
        assert!(matches!(
            next_event(&mut events, "clear restart").await,
            ConfigChangeEvent::RestartRequired { required: false }
        ));

        set_field(&mut connection, "TACPLUS_FORWARDER|global", "local_listen_port", "0").await;
        assert!(matches!(
            next_event(&mut events, "rejected candidate").await,
            ConfigChangeEvent::CandidateRejected
        ));
    }
}
