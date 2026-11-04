//! Isolated Redis tests. No host ConfigDB instance is used.

use std::collections::BTreeMap;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use redis::IntoConnectionInfo;
use tacacsrs_config::source::{ConfigChangeEvent, ConfigDatastore};
use tacacsrs_kubesonic::datastore::KubeSonicConfigDb;
use tacacsrs_kubesonic::environment::{Environment, SourceSettings};
use tacacsrs_kubesonic::registration::LoopbackRegistration;

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
