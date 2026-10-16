//! Canonical SONiC configuration observation and one-shot loading.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use futures_util::{future::BoxFuture, FutureExt, StreamExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tacacsrs_config::{TacacsPlus, ValidationOptions, ValidationRelaxation};
use tacacsrs_config::source::{
    ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigDatastore, ConfigDelta,
    ConfigObservation, DatastoreRuntimePolicy, InitialLoadPolicy,
};

use crate::{
    SonicConnection, SonicForwarderSettings, map_sonic_tables_to_tacacs_plus, read_tacacs_tables,
};

/// SONiC ConfigDB-backed [`ConfigDatastore`] implementation.
///
/// This datastore reads TACACS+ compatibility, TLS server, and forwarder tables
/// from CONFIG_DB. It emits a [`tacacsrs_config::source::ConfigChange`] after a
/// debounced change to a `TACPLUS` key.
///
/// The datastore stores connection configuration instead of a live client.
/// [`load`](Self::load) and [`observe`](Self::observe) open Redis
/// connections only when required. Thus, the daemon can continue after SONiC
/// restarts `database.service`.
pub struct SonicConfigDb {
    settings: SonicConnection,
    bound_forwarder: Option<SonicForwarderSettings>,
}

impl SonicConfigDb {
    /// Creates a datastore with the supplied connection configuration.
    #[must_use]
    pub fn new(settings: SonicConnection) -> Self {
        Self {
            settings,
            bound_forwarder: None,
        }
    }

    /// Creates a datastore that compares new forwarder snapshots with the
    /// configuration used to bind service listeners.
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
    async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
        Ok(Box::new(SonicObservation::open(self.settings.clone(), self.bound_forwarder).await?))
    }

    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        DatastoreRuntimePolicy::new(
            InitialLoadPolicy::RetryUntilAvailable,
            ChangeNotificationMode::Continuous,
        )
    }

    fn validation_options(&self) -> ValidationOptions {
        ValidationOptions::new()
            .with_relaxation(ValidationRelaxation::AllowPlainTcpWithoutSharedSecret)
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

    fn label(&self) -> &'static str {
        "sonic-configdb"
    }
}

struct SonicObservation {
    settings: SonicConnection,
    bound_forwarder: Option<SonicForwarderSettings>,
    signals: watch::Receiver<()>,
    pump: JoinHandle<()>,
    previous: Option<Arc<TacacsPlus>>,
    restart: Option<bool>,
    pending: bool,
    debounce_until: Option<Instant>,
    reload: Option<BoxFuture<'static, anyhow::Result<ReloadedCandidate>>>,
}

impl SonicObservation {
    async fn open(
        settings: SonicConnection,
        bound_forwarder: Option<SonicForwarderSettings>,
    ) -> anyhow::Result<Self> {
        let client = redis::Client::open(settings.url.as_str())
            .context("invalid ConfigDB connection string")?;
        let mut pubsub = client
            .get_async_pubsub()
            .await
            .context("open ConfigDB observation")?;
        pubsub
            .psubscribe(settings.keyspace_pattern())
            .await
            .context("subscribe to ConfigDB changes")?;
        let (events, signals) = watch::channel(());
        let pump = tokio::spawn(async move {
            let mut messages = pubsub.on_message();
            loop {
                tokio::select! {
                    biased;
                    () = events.closed() => break,
                    message = messages.next() => {
                        if message.is_none() { break; }
                        events.send_replace(());
                    }
                }
            }
        });
        Ok(Self {
            settings,
            bound_forwarder,
            signals,
            pump,
            previous: None,
            restart: None,
            pending: true,
            debounce_until: None,
            reload: None,
        })
    }

    async fn read_candidate(&mut self) -> anyhow::Result<ReloadedCandidate> {
        if self.reload.is_none() {
            if let Some(deadline) = self.debounce_until {
                tokio::time::sleep_until(deadline).await;
            }
            self.signals.borrow_and_update();
            let settings = self.settings.clone();
            self.reload = Some(async move { reload_with_retry(&settings).await }.boxed());
        }
        let mut connection = self.signals.clone();
        let closed = async move { while connection.changed().await.is_ok() {} };
        let candidate = tokio::select! {
            biased;
            () = closed => anyhow::bail!("ConfigDB observation disconnected"),
            candidate = self.reload.as_mut().context("ConfigDB reload is missing")? => candidate,
        };
        self.reload = None;
        self.pending = false;
        self.debounce_until = None;
        candidate
    }
}

impl Drop for SonicObservation {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

#[async_trait]
impl ConfigObservation for SonicObservation {
    async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
        self.signals
            .has_changed()
            .context("ConfigDB observation disconnected")?;
        if let Some(required) = self.restart.take() {
            return Ok(Some(ConfigChangeEvent::RestartRequired { required }));
        }
        if !self.pending {
            self.signals
                .changed()
                .await
                .context("ConfigDB observation disconnected")?;
            self.pending = true;
            self.debounce_until = Some(
                Instant::now()
                    .checked_add(self.settings.debounce)
                    .context("ConfigDB debounce exceeds the clock range")?,
            );
        }
        let candidate = self.read_candidate().await;
        self.signals
            .has_changed()
            .context("ConfigDB observation disconnected")?;
        let Ok(candidate) = candidate else {
            log::warn!("Rejected ConfigDB candidate. Keeping the previous configuration");
            return Ok(Some(ConfigChangeEvent::CandidateRejected));
        };
        let required = self
            .bound_forwarder
            .is_some_and(|bound| candidate.forwarder != Some(bound));
        let snapshot = Arc::new(candidate.config);
        let change = config_change(self.previous.as_deref(), snapshot.clone());
        self.previous = Some(snapshot);
        if let Some(change) = change {
            self.restart = Some(required);
            Ok(Some(ConfigChangeEvent::Changed(change)))
        } else {
            Ok(Some(ConfigChangeEvent::RestartRequired { required }))
        }
    }
}

fn config_change(previous: Option<&TacacsPlus>, snapshot: Arc<TacacsPlus>) -> Option<ConfigChange> {
    let is_baseline = previous.is_none();
    let delta = ConfigDelta::diff(previous, &snapshot);
    (is_baseline || !delta.is_empty()).then_some(ConfigChange {
        config: snapshot,
        delta,
    })
}

/// Candidate loaded by the change subscriber after a reconnect.
///
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
                log::warn!("SONiC ConfigDB reload attempt {attempt}/{MAX_ATTEMPTS} failed");
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

    use redis::AsyncCommands;
    use tokio::time::timeout;

    use super::*;
    use crate::sonic_server_name;

    #[test]
    fn config_change_emits_baseline_and_suppresses_unchanged_snapshot() {
        let snapshot = Arc::new(TacacsPlus::empty());

        assert!(config_change(None, Arc::clone(&snapshot)).is_some());
        assert!(config_change(Some(&snapshot), Arc::clone(&snapshot)).is_none());
    }

    async fn next_event(
        events: &mut Box<dyn ConfigObservation>,
        context: &str,
    ) -> ConfigChangeEvent {
        timeout(Duration::from_secs(5), events.next())
            .await
            .unwrap_or_else(|_| panic!("{context} timeout"))
            .unwrap_or_else(|_| panic!("{context} observation failed"))
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
    async fn redis_drop_during_native_reload_closes_all_observation_connections() {
        let Ok(url) = std::env::var("TACACSRS_SONIC_TEST_REDIS_URL") else {
            return;
        };
        let settings = SonicConnection {
            url,
            db_index: 15,
            debounce: Duration::ZERO,
            credential_watch_root: None,
        };
        let mut connection = settings.connect().await.unwrap();
        seed_redis(&mut connection).await;
        let mut observation = SonicObservation::open(settings, None).await.unwrap();
        let _: () = redis::cmd("CLIENT")
            .arg("PAUSE")
            .arg(5000)
            .arg("WRITE")
            .query_async(&mut connection)
            .await
            .unwrap();
        {
            let reload = observation.next();
            tokio::pin!(reload);
            tokio::select! {
                result = &mut reload => panic!("native reload must remain pending: {result:?}"),
                result = timeout(Duration::from_secs(1), async {
                    loop {
                        let clients: String = redis::cmd("CLIENT").arg("LIST").query_async(&mut connection).await.unwrap();
                        if clients.lines().count() >= 3 { break; }
                        tokio::task::yield_now().await;
                    }
                }) => result.expect("native reload connection must open"),
            }
        }
        drop(observation);
        let closed = timeout(Duration::from_secs(1), async {
            loop {
                let clients: String = redis::cmd("CLIENT")
                    .arg("LIST")
                    .query_async(&mut connection)
                    .await
                    .unwrap();
                if clients.lines().count() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let _: () = redis::cmd("CLIENT")
            .arg("UNPAUSE")
            .query_async(&mut connection)
            .await
            .unwrap();
        closed.expect("drop must close both Pub/Sub and pending snapshot connections");
    }

    #[tokio::test]
    async fn redis_cancelled_reload_retains_invalidation_and_reconciles_latest_snapshot() {
        let Ok(url) = std::env::var("TACACSRS_SONIC_TEST_REDIS_URL") else {
            return;
        };
        let settings = SonicConnection {
            url,
            db_index: 15,
            debounce: Duration::ZERO,
            credential_watch_root: None,
        };
        let mut connection = settings.connect().await.unwrap();
        seed_redis(&mut connection).await;
        let mut observation = SonicObservation::open(settings.clone(), None)
            .await
            .unwrap();
        let baseline = try_reload(&settings).await.unwrap();
        let (release, pending) = tokio::sync::oneshot::channel::<()>();
        observation.reload = Some(
            async move {
                pending.await.unwrap();
                Ok(baseline)
            }
            .boxed(),
        );
        {
            let next = observation.next();
            tokio::pin!(next);
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(next.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        set_field(&mut connection, "TACPLUS_SERVER|192.0.2.10", "timeout", "9").await;
        timeout(Duration::from_secs(1), async {
            while !observation.signals.has_changed().unwrap() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        release.send(()).unwrap();
        let Some(ConfigChangeEvent::Changed(first)) = observation.next().await.unwrap() else {
            panic!("baseline expected");
        };
        assert_ne!(
            first
                .config
                .server
                .iter()
                .find(|server| server.address == "192.0.2.10")
                .unwrap()
                .timeout,
            9
        );
        observation.next().await.unwrap();
        let Some(ConfigChangeEvent::Changed(latest)) = observation.next().await.unwrap() else {
            panic!("replacement expected");
        };
        assert_eq!(
            latest
                .config
                .server
                .iter()
                .find(|server| server.address == "192.0.2.10")
                .unwrap()
                .timeout,
            9
        );
        let pump = observation.pump.abort_handle();
        drop(observation);
        timeout(Duration::from_secs(1), async {
            while !pump.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("notification pump must stop");
    }

    #[tokio::test]
    async fn redis_disconnect_interrupts_pending_reload_and_reopen_reads_fresh_baseline() {
        let Ok(url) = std::env::var("TACACSRS_SONIC_TEST_REDIS_URL") else {
            return;
        };
        let settings = SonicConnection {
            url,
            db_index: 15,
            debounce: Duration::ZERO,
            credential_watch_root: None,
        };
        let mut connection = settings.connect().await.unwrap();
        seed_redis(&mut connection).await;
        let mut observation = SonicObservation::open(settings.clone(), None)
            .await
            .unwrap();
        observation.reload = Some(std::future::pending().boxed());
        let _: i64 = redis::cmd("CLIENT")
            .arg("KILL")
            .arg("TYPE")
            .arg("PUBSUB")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(timeout(Duration::from_secs(1), observation.next())
            .await
            .unwrap()
            .is_err());
        drop(observation);
        set_field(&mut connection, "TACPLUS_SERVER|192.0.2.10", "timeout", "12").await;
        let mut observation = SonicObservation::open(settings, None).await.unwrap();
        let Some(ConfigChangeEvent::Changed(baseline)) = observation.next().await.unwrap() else {
            panic!("fresh baseline expected");
        };
        assert_eq!(
            baseline
                .config
                .server
                .iter()
                .find(|server| server.address == "192.0.2.10")
                .unwrap()
                .timeout,
            12
        );
    }

    #[tokio::test]
    async fn redis_idle_subscription_drop_closes_pubsub_connection() {
        let Ok(url) = std::env::var("TACACSRS_SONIC_TEST_REDIS_URL") else {
            return;
        };
        let settings = SonicConnection {
            url,
            db_index: 15,
            debounce: Duration::ZERO,
            credential_watch_root: None,
        };
        let mut connection = settings.connect().await.unwrap();
        seed_redis(&mut connection).await;
        let datastore = SonicConfigDb::new(settings);
        let mut events = datastore.observe().await.unwrap();
        next_event(&mut events, "baseline").await;
        next_event(&mut events, "baseline restart").await;
        drop(events);
        timeout(Duration::from_secs(1), async {
            loop {
                let clients: String = redis::cmd("CLIENT")
                    .arg("LIST")
                    .arg("TYPE")
                    .arg("PUBSUB")
                    .query_async(&mut connection)
                    .await
                    .unwrap();
                if clients.trim().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping an idle subscription must close its Redis connection");
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
        let mut events = datastore.observe().await.expect("subscribe");

        // subscribe() establishes the subscription before it emits the baseline.
        assert!(matches!(
            next_event(&mut events, "initial baseline change").await,
            ConfigChangeEvent::Changed(_)
        ));
        assert!(matches!(
            next_event(&mut events, "initial baseline restart").await,
            ConfigChangeEvent::RestartRequired { required: false }
        ));

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
            next_event(&mut events, "clear restart").await,
            ConfigChangeEvent::RestartRequired { required: false }
        ));

        set_field(&mut connection, "TACPLUS_FORWARDER|global", "local_listen_port", "0").await;
        assert!(matches!(
            next_event(&mut events, "rejected candidate").await,
            ConfigChangeEvent::CandidateRejected
        ));
        set_field(&mut connection, "TACPLUS_FORWARDER|global", "local_listen_port", "49").await;
        connection
            .del::<_, ()>(&["TACPLUS_SERVER|192.0.2.10", "TACPLUS_SERVER_TLS|192.0.2.20"])
            .await
            .unwrap();
        let ConfigChangeEvent::Changed(empty) =
            next_event(&mut events, "remove final servers").await
        else {
            panic!("empty snapshot expected");
        };
        assert_eq!(empty.config.server.len(), 0);
        assert_eq!(empty.delta.removed_servers.len(), 2);
    }
}
