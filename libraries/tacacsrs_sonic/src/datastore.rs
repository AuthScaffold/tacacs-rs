//! Canonical SONiC configuration observation and one-shot loading.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use futures_util::{FutureExt, StreamExt};
use tacacsrs_config::local_services::LocalServicesPatch;
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_config::{TacacsPlus, ValidationOptions, ValidationRelaxation};
use tacacsrs_config::source::{
    ChangeNotificationMode, ConfigChangeEvent, ConfigDatastore, ConfigObservation,
    ObservationSchedule, ObservedSnapshot, SignalObservation, SourceBehavior,
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
    listener_patch: Option<LocalServicesPatch>,
}

impl SonicConfigDb {
    /// Creates a datastore with the supplied connection configuration.
    ///
    /// The datastore does not own the local services. Each change keeps the
    /// local services of the runtime.
    #[must_use]
    pub fn new(settings: SonicConnection) -> Self {
        Self {
            settings,
            listener_patch: None,
        }
    }

    /// Creates a datastore that owns the local services.
    ///
    /// Each change contains the local services of the forwarder row, with
    /// `patch` applied. Without a forwarder row, the proxy is enabled and
    /// waits for its endpoint. If the patch sets a proxy endpoint, the
    /// datastore rejects a forwarder row with a different endpoint.
    #[must_use]
    pub fn with_listener_patch(settings: SonicConnection, patch: LocalServicesPatch) -> Self {
        Self {
            settings,
            listener_patch: Some(patch),
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
        Ok(Box::new(
            SonicObservation::open(self.settings.clone(), self.listener_patch.clone()).await?,
        ))
    }

    fn behavior(&self) -> SourceBehavior {
        SourceBehavior::new(ChangeNotificationMode::Continuous)
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

/// Returns the local services of `forwarder` with `patch` applied.
///
/// Without a forwarder row, the proxy is enabled and has no endpoint.
fn forwarder_local_services(
    patch: &LocalServicesPatch,
    forwarder: Option<SonicForwarderSettings>,
) -> anyhow::Result<LocalServices> {
    match forwarder {
        Some(row) => row.local_services_with(patch),
        None => Ok(crate::mapping::deferred_local_services(patch)?.0),
    }
}

const fn observation_schedule(settings: &SonicConnection) -> ObservationSchedule {
    ObservationSchedule {
        debounce: settings.debounce,
        max_delay: None,
        reconcile_interval: Some(settings.reconcile_interval),
        retry_interval: Some(settings.retry_interval),
    }
}

struct SonicObservation {
    inner: SignalObservation,
}

impl SonicObservation {
    async fn open(
        settings: SonicConnection,
        listener_patch: Option<LocalServicesPatch>,
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
        let schedule = observation_schedule(&settings);
        let notifications = pubsub.into_on_message().map(|_| ());
        let inner = SignalObservation::spawn(
            notifications,
            schedule,
            "ConfigDB observation disconnected",
            move || {
                let settings = settings.clone();
                let listener_patch = listener_patch.clone();
                async move {
                    load_observed_snapshot(&settings, listener_patch.as_ref())
                        .await
                        .map_err(|_| {
                            log::warn!(
                                "Rejected ConfigDB candidate. Keeping the previous configuration"
                            );
                        })
                }
                .boxed()
            },
        );
        Ok(Self { inner })
    }
}

#[async_trait]
impl ConfigObservation for SonicObservation {
    async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
        self.inner.next().await
    }

    fn record_rejection(&mut self) {
        self.inner.record_rejection();
    }
}

async fn load_observed_snapshot(
    settings: &SonicConnection,
    listener_patch: Option<&LocalServicesPatch>,
) -> anyhow::Result<ObservedSnapshot> {
    let candidate = reload_with_retry(settings).await?;
    candidate_to_observed(candidate, listener_patch)
}

fn candidate_to_observed(
    candidate: ReloadedCandidate,
    listener_patch: Option<&LocalServicesPatch>,
) -> anyhow::Result<ObservedSnapshot> {
    let local_services = listener_patch
        .map(|patch| forwarder_local_services(patch, candidate.forwarder))
        .transpose()?
        .map(Arc::new);
    Ok(ObservedSnapshot {
        config: Arc::new(candidate.config),
        local_services,
        runtime_policy: None,
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
    use tacacsrs_config::source::ConfigChange;
    use tokio::time::timeout;

    use super::*;
    use crate::sonic_server_name;

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

    async fn assert_rejected_forwarder_recovery(
        connection: &mut redis::aio::MultiplexedConnection,
        events: &mut Box<dyn ConfigObservation>,
    ) {
        set_field(connection, "TACPLUS_FORWARDER|global", "local_listen_port", "0").await;
        assert!(matches!(
            next_event(events, "rejected candidate").await,
            ConfigChangeEvent::CandidateRejected
        ));
        set_field(connection, "TACPLUS_FORWARDER|global", "local_listen_port", "49").await;
        let ConfigChangeEvent::Changed(recovered) =
            next_event(events, "rejected candidate recovery").await
        else {
            panic!("recovery change expected");
        };
        assert!(recovered.delta.is_empty());
        assert_eq!(recovered.config.server.len(), 2);
    }

    fn forwarder(port: u16) -> SonicForwarderSettings {
        SonicForwarderSettings::from_hash(&crate::SonicHash::from([
            ("local_listen_address".to_owned(), "127.0.0.1".to_owned()),
            ("local_listen_port".to_owned(), port.to_string()),
        ]))
        .unwrap()
        .unwrap()
    }

    fn proxy_endpoint(local_services: &LocalServices) -> Option<&str> {
        local_services.tacacs_proxy_endpoint.as_deref()
    }

    #[test]
    fn forwarder_row_gives_the_proxy_endpoint_and_a_missing_row_waits() {
        let patch = LocalServicesPatch::default();

        let waiting = forwarder_local_services(&patch, None).unwrap();
        assert!(waiting.tacacs_proxy_enabled);
        assert_eq!(proxy_endpoint(&waiting), None);

        let bound = forwarder_local_services(&patch, Some(forwarder(50))).unwrap();
        assert_eq!(proxy_endpoint(&bound), Some("127.0.0.1:50"));
    }

    #[test]
    fn a_patch_endpoint_rejects_a_conflicting_forwarder_row() {
        let patch = LocalServicesPatch {
            tacacs_proxy_endpoint: Some("127.0.0.1:49".to_owned()),
            ..Default::default()
        };

        assert!(forwarder_local_services(&patch, Some(forwarder(50))).is_err());
        let accepted = forwarder_local_services(&patch, Some(forwarder(49))).unwrap();
        assert_eq!(proxy_endpoint(&accepted), Some("127.0.0.1:49"));
    }

    #[test]
    fn runtime_policy_retries_and_maintains_continuous_notifications() {
        let settings = SonicConnection::default();
        let schedule = observation_schedule(&settings);
        assert_eq!(schedule.debounce, Duration::from_millis(250));
        assert_eq!(schedule.retry_interval, Some(Duration::from_secs(5)));
        assert_eq!(schedule.reconcile_interval, Some(Duration::from_secs(60)));

        let datastore = SonicConfigDb::new(settings);

        assert_eq!(datastore.behavior(), SourceBehavior::new(ChangeNotificationMode::Continuous));
    }

    fn test_settings(url: String, debounce: Duration) -> SonicConnection {
        SonicConnection {
            url,
            db_index: 15,
            debounce,
            credential_watch_root: None,
            ..SonicConnection::default()
        }
    }

    #[tokio::test]
    async fn redis_drop_during_native_reload_closes_all_observation_connections() {
        let Ok(url) = std::env::var("TACACSRS_SONIC_TEST_REDIS_URL") else {
            return;
        };
        let settings = test_settings(url, Duration::ZERO);
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
        let settings = test_settings(url, Duration::ZERO);
        let mut connection = settings.connect().await.unwrap();
        seed_redis(&mut connection).await;
        let mut observation = SonicObservation::open(settings.clone(), None)
            .await
            .unwrap();
        let baseline = candidate_to_observed(try_reload(&settings).await.unwrap(), None).unwrap();
        let (release, pending) = tokio::sync::oneshot::channel::<()>();
        observation.inner.replace_pending_read(
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
            while !observation.inner.has_pending_signal().unwrap() {
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
        let pump = observation.inner.pump_abort_handle();
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
        let settings = test_settings(url, Duration::ZERO);
        let mut connection = settings.connect().await.unwrap();
        seed_redis(&mut connection).await;
        let mut observation = SonicObservation::open(settings.clone(), None)
            .await
            .unwrap();
        observation
            .inner
            .replace_pending_read(std::future::pending().boxed());
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
        let settings = test_settings(url, Duration::ZERO);
        let mut connection = settings.connect().await.unwrap();
        seed_redis(&mut connection).await;
        let datastore = SonicConfigDb::new(settings);
        let mut events = datastore.observe().await.unwrap();
        next_event(&mut events, "baseline").await;
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

    fn changed(event: ConfigChangeEvent) -> ConfigChange {
        let ConfigChangeEvent::Changed(change) = event else {
            panic!("changed event expected");
        };
        change
    }

    fn changed_proxy_endpoint(change: &ConfigChange) -> Option<&str> {
        proxy_endpoint(
            change
                .local_services
                .as_deref()
                .expect("local services expected"),
        )
    }

    #[tokio::test]
    async fn redis_missing_forwarder_waits_for_the_proxy_endpoint_until_the_row_arrives() {
        let Ok(url) = std::env::var("TACACSRS_SONIC_TEST_REDIS_URL") else {
            return;
        };
        let settings = test_settings(url, Duration::from_millis(20));
        let mut connection = settings.connect().await.expect("connect test Redis");
        seed_redis(&mut connection).await;
        connection
            .del::<_, ()>("TACPLUS_FORWARDER|global")
            .await
            .expect("delete forwarder");

        let datastore = SonicConfigDb::with_listener_patch(settings, LocalServicesPatch::default());
        let mut events = datastore.observe().await.expect("subscribe");
        let baseline = changed(next_event(&mut events, "missing forwarder").await);
        assert_eq!(baseline.config.server.len(), 2);
        let waiting = baseline.local_services.as_deref().expect("local services");
        assert!(waiting.tacacs_proxy_enabled);
        assert_eq!(proxy_endpoint(waiting), None);

        connection
            .hset_multiple::<_, _, _, ()>(
                "TACPLUS_FORWARDER|global",
                &[
                    ("local_listen_address", "127.0.0.1"),
                    ("local_listen_port", "4949"),
                ],
            )
            .await
            .expect("add forwarder");
        let bound = changed(next_event(&mut events, "forwarder arrives").await);
        assert!(bound.delta.is_empty());
        assert_eq!(changed_proxy_endpoint(&bound), Some("127.0.0.1:4949"));
    }

    #[tokio::test]
    async fn redis_forwarder_changes_move_the_proxy_with_server_reload() {
        let Ok(url) = std::env::var("TACACSRS_SONIC_TEST_REDIS_URL") else {
            return;
        };
        let settings = test_settings(url, Duration::from_millis(20));
        let mut connection = settings.connect().await.expect("connect test Redis");
        seed_redis(&mut connection).await;

        let datastore = SonicConfigDb::with_listener_patch(settings, LocalServicesPatch::default());
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

        // observe() establishes the subscription before it emits the baseline.
        let baseline = changed(next_event(&mut events, "initial baseline change").await);
        assert_eq!(changed_proxy_endpoint(&baseline), Some("127.0.0.1:49"));

        set_field(&mut connection, "TACPLUS_FORWARDER|global", "local_listen_port", "50").await;
        set_field(&mut connection, "TACPLUS_SERVER|192.0.2.10", "timeout", "6").await;
        set_field(&mut connection, "TACPLUS_SERVER_TLS|192.0.2.20", "timeout", "7").await;
        let changed_event = changed(next_event(&mut events, "changed event").await);
        assert_eq!(changed_proxy_endpoint(&changed_event), Some("127.0.0.1:50"));
        assert_eq!(changed_event.config.server.len(), 2);
        assert_eq!(changed_event.config.server[0].address, "192.0.2.20");
        assert_eq!(changed_event.config.server[0].timeout, 7);
        assert_eq!(changed_event.config.server[1].name, sonic_server_name("192.0.2.10"));
        assert_eq!(changed_event.config.server[1].timeout, 6);
        assert!(changed_event
            .delta
            .modified_servers
            .contains(&sonic_server_name("192.0.2.10")));
        assert!(changed_event
            .delta
            .modified_servers
            .contains(&sonic_server_name("192.0.2.20")));

        connection
            .del::<_, ()>("TACPLUS_FORWARDER|global")
            .await
            .expect("delete forwarder");
        let removed = changed(next_event(&mut events, "forwarder deletion").await);
        assert!(removed.delta.is_empty());
        assert_eq!(changed_proxy_endpoint(&removed), None);

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
        let restored = changed(next_event(&mut events, "forwarder restore").await);
        assert_eq!(changed_proxy_endpoint(&restored), Some("127.0.0.1:49"));

        assert_rejected_forwarder_recovery(&mut connection, &mut events).await;

        connection
            .del::<_, ()>(&["TACPLUS_SERVER|192.0.2.10", "TACPLUS_SERVER_TLS|192.0.2.20"])
            .await
            .unwrap();
        let empty = changed(next_event(&mut events, "remove final servers").await);
        assert_eq!(empty.config.server.len(), 0);
        assert_eq!(empty.delta.removed_servers.len(), 2);
    }
}
