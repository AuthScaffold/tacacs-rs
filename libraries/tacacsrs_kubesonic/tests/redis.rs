//! Isolated Redis tests. No host ConfigDB instance is used.

use std::collections::BTreeMap;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use redis::IntoConnectionInfo;
use tacacsrs_config::source::{ConfigChangeEvent, ConfigDatastore};
use tacacsrs_kubesonic::datastore::KubeSonicConfigDb;
use tacacsrs_kubesonic::environment::{Environment, SourceSettings};
use tacacsrs_kubesonic::registration::LoopbackRegistration;
use tacacsrs_provider::CompanionContext;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

struct Redis {
    child: Child,
    _directory: tempfile::TempDir,
    settings: SourceSettings,
}

impl Drop for Redis {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Redis {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("redis.sock");
        let child = Command::new("redis-server")
            .args([
                "--port",
                "0",
                "--save",
                "",
                "--appendonly",
                "no",
                "--unixsocket",
            ])
            .arg(&socket)
            .args(["--notify-keyspace-events", ""])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Redis is required");
        let mut settings = Environment::parse(BTreeMap::new()).unwrap().source;
        settings.socket = socket;
        settings.reconcile_interval = Duration::from_millis(50);
        settings.retry_interval = Duration::from_millis(25);
        let server = Self {
            child,
            _directory: directory,
            settings,
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if server.connect().await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Redis startup deadline");
        server
    }

    async fn connect(&self) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
        let info = redis::ConnectionAddr::Unix(self.settings.socket.clone())
            .into_connection_info()?
            .set_redis_settings(
                redis::RedisConnectionInfo::default().set_db(self.settings.database),
            );
        redis::Client::open(info)?
            .get_multiplexed_async_connection()
            .await
    }

    async fn command<T: redis::FromRedisValue>(&self, command: &redis::Cmd) -> T {
        command
            .query_async(&mut self.connect().await.unwrap())
            .await
            .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn observes_complete_snapshots_and_final_removal_without_notifications() {
    let redis = Redis::start().await;
    redis
        .command::<()>(
            redis::cmd("HSET")
                .arg("TACPLUS_SERVER|192.0.2.1")
                .arg("priority")
                .arg(2),
        )
        .await;
    let datastore = KubeSonicConfigDb::new(redis.settings.clone()).unwrap();
    let mut observation = datastore.observe().await.unwrap();
    let next = tokio::time::timeout(Duration::from_secs(2), observation.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(next, ConfigChangeEvent::Changed(change) if change.config.server.len() == 1));
    redis
        .command::<()>(
            redis::cmd("HSET")
                .arg("TACPLUS_SERVER|192.0.2.1")
                .arg("priority")
                .arg(65),
        )
        .await;
    let next = tokio::time::timeout(Duration::from_secs(2), observation.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(next, ConfigChangeEvent::CandidateRejected));
    redis
        .command::<()>(redis::cmd("DEL").arg("TACPLUS_SERVER|192.0.2.1"))
        .await;
    let next = tokio::time::timeout(Duration::from_secs(2), observation.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(next, ConfigChangeEvent::Changed(change) if change.config.server.is_empty()));
    assert!(datastore.load().await.unwrap().server.is_empty());
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn registration_owns_only_complete_unchanged_rows() {
    let redis = Redis::start().await;
    let key = "TACPLUS_SERVER|127.0.0.1";
    let mut registration = LoopbackRegistration::new(redis.settings.clone(), 32, 5049);
    registration.remove_stale().await.unwrap();
    registration.reconcile(false).await.unwrap();
    assert!(!redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await);
    registration.reconcile(true).await.unwrap();
    let values: Vec<String> = redis
        .command(redis::cmd("HMGET").arg(key).arg("tcp_port").arg("priority"))
        .await;
    assert_eq!(values, ["5049", "32"]);
    redis
        .command::<()>(redis::cmd("HSET").arg(key).arg("owner").arg("external"))
        .await;
    registration.cleanup().await.unwrap();
    assert!(redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await);
    redis.command::<()>(redis::cmd("DEL").arg(key)).await;
    registration.reconcile(true).await.unwrap();
    registration.cleanup().await.unwrap();
    assert!(!redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await);
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn uncertain_registration_cannot_report_successful_cleanup() {
    let redis = Redis::start().await;
    let mut settings = redis.settings.clone();
    settings.command_timeout = Duration::from_millis(20);
    let mut registration = LoopbackRegistration::new(settings, 32, 5049);
    redis
        .command::<()>(redis::cmd("CLIENT").arg("PAUSE").arg(500).arg("WRITE"))
        .await;
    assert!(registration.reconcile(true).await.is_err());
    assert!(registration.cleanup().await.is_err());
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn companion_waits_for_readiness_and_cleans_up_its_row() {
    let redis = Redis::start().await;
    let key = "TACPLUS_SERVER|127.0.0.1";
    redis
        .command::<()>(redis::cmd("HSET").arg(key).arg("old").arg("value"))
        .await;
    let mut input = Environment::parse(BTreeMap::new()).unwrap();
    input.source = redis.settings.clone();
    input.loopback.enabled = true;
    input.loopback.retry_interval = Duration::from_millis(25);
    let mut bundle = tacacsrs_kubesonic::prepare(input).unwrap();
    assert!(redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await);
    let (sender, receiver) = watch::channel(false);
    let cancellation = CancellationToken::new();
    let companion = bundle.companions.pop().unwrap();
    let handle = tokio::spawn(companion.run(CompanionContext {
        ready: receiver,
        cancellation: cancellation.clone(),
    }));
    tokio::time::timeout(Duration::from_secs(2), async {
        while redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    sender.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    sender.send(false).unwrap();
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert!(redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await);
    cancellation.cancel();
    handle.await.unwrap().unwrap();
    assert!(!redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await);
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn cancelled_companion_does_not_remove_stale_row() {
    let redis = Redis::start().await;
    let key = "TACPLUS_SERVER|127.0.0.1";
    redis
        .command::<()>(redis::cmd("HSET").arg(key).arg("old").arg("value"))
        .await;
    let mut input = Environment::parse(BTreeMap::new()).unwrap();
    input.source = redis.settings.clone();
    input.loopback.enabled = true;
    let mut bundle = tacacsrs_kubesonic::prepare(input).unwrap();
    let (_sender, ready) = watch::channel(false);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    bundle
        .companions
        .pop()
        .unwrap()
        .run(CompanionContext {
            ready,
            cancellation,
        })
        .await
        .unwrap();
    assert!(redis.command::<bool>(redis::cmd("EXISTS").arg(key)).await);
}
