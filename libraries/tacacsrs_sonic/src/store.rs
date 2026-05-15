//! Async Redis I/O for SONiC ConfigDB.
//!
//! This module is a thin wrapper around [`redis::aio::MultiplexedConnection`]
//! that reads the TACACS+ tables in a single call (`HGETALL` per table key,
//! preceded by a `KEYS` scan) and exposes a Tokio task that subscribes to
//! Redis keyspace notifications on `__keyspace@<db>__:TACPLUS*`.

use std::time::Duration;

use anyhow::Context;
use futures_util::StreamExt;
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use tokio::sync::mpsc;

use crate::mapping::{SonicHash, SonicTacacsTables};

/// Default Redis URL when the operator does not override it.
///
/// SONiC ships Redis with a Unix-domain socket at `/var/run/redis/redis.sock`
/// and uses database index `4` for `CONFIG_DB`.
pub const DEFAULT_REDIS_URL: &str = "unix:///var/run/redis/redis.sock?db=4";

/// CONFIG_DB key prefix for the per-server table.
pub const TACPLUS_SERVER_TABLE: &str = "TACPLUS_SERVER";

/// CONFIG_DB key prefix for the global table.
pub const TACPLUS_GLOBAL_TABLE: &str = "TACPLUS";

/// Connection settings for the SONiC ConfigDB Redis instance.
#[derive(Debug, Clone)]
pub struct SonicConnection {
    /// Connection string passed to [`redis::Client::open`].
    pub url: String,
    /// Database index that holds CONFIG_DB. SONiC defaults to `4`.
    pub db_index: i64,
    /// Debounce window applied to keyspace notifications. Multiple changes
    /// arriving within this window are coalesced into a single reload.
    pub debounce: Duration,
}

impl Default for SonicConnection {
    fn default() -> Self {
        Self {
            url: DEFAULT_REDIS_URL.to_string(),
            db_index: 4,
            debounce: Duration::from_millis(250),
        }
    }
}

impl SonicConnection {
    /// Open a new multiplexed async connection to ConfigDB.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid or the connection cannot be
    /// established.
    pub async fn connect(&self) -> anyhow::Result<MultiplexedConnection> {
        let client = redis::Client::open(self.url.as_str())
            .with_context(|| format!("Invalid Redis URL '{}'", self.url))?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .with_context(|| format!("Failed to connect to SONiC ConfigDB at '{}'", self.url))?;
        redis::cmd("SELECT")
            .arg(self.db_index)
            .query_async::<()>(&mut conn)
            .await
            .with_context(|| format!("Failed to select SONiC ConfigDB index {}", self.db_index))?;
        Ok(conn)
    }

    /// The keyspace-notification pattern that covers TACPLUS / TACPLUS_SERVER.
    #[must_use]
    pub fn keyspace_pattern(&self) -> String {
        format!("__keyspace@{}__:TACPLUS*", self.db_index)
    }
}

/// Read both TACACS+ tables from ConfigDB into an in-memory snapshot.
///
/// # Errors
///
/// Returns an error if the Redis commands fail. Missing tables are not an
/// error here — the caller can decide whether an empty snapshot should be
/// rejected (the mapping function rejects it by default).
pub async fn read_tacacs_tables(
    conn: &mut MultiplexedConnection,
) -> anyhow::Result<SonicTacacsTables> {
    let global_key = format!("{TACPLUS_GLOBAL_TABLE}|global");
    let global: SonicHash = conn
        .hgetall(&global_key)
        .await
        .with_context(|| format!("HGETALL failed for {global_key}"))?;

    let server_pattern = format!("{TACPLUS_SERVER_TABLE}|*");
    let server_keys: Vec<String> = conn
        .keys(&server_pattern)
        .await
        .with_context(|| format!("KEYS failed for {server_pattern}"))?;

    let mut servers = std::collections::BTreeMap::new();
    for key in server_keys {
        let Some(addr) = key.strip_prefix(&format!("{TACPLUS_SERVER_TABLE}|")) else {
            continue;
        };
        let fields: SonicHash = conn
            .hgetall(&key)
            .await
            .with_context(|| format!("HGETALL failed for {key}"))?;
        servers.insert(addr.to_string(), fields);
    }

    Ok(SonicTacacsTables::new(global, servers))
}

/// Spawn a background task that subscribes to TACPLUS keyspace notifications
/// and forwards a unit signal to the receiver each time a relevant key
/// changes.
///
/// SONiC requires that keyspace notifications be enabled on the Redis server
/// (`CONFIG SET notify-keyspace-events KEA` or equivalent in
/// `/etc/redis/redis.conf`). If notifications are disabled the task will
/// still run but no events will be delivered.
///
/// The returned receiver yields one signal per coalesced change window. The
/// task terminates when the receiver is dropped or when the underlying Redis
/// connection breaks.
///
/// # Errors
///
/// Returns an error if the pubsub connection cannot be established or the
/// subscription cannot be installed.
pub async fn spawn_change_notifier(
    settings: SonicConnection,
) -> anyhow::Result<mpsc::Receiver<()>> {
    let client = redis::Client::open(settings.url.as_str())
        .with_context(|| format!("Invalid Redis URL '{}'", settings.url))?;
    let mut pubsub = client
        .get_async_pubsub()
        .await
        .with_context(|| format!("Failed to open pubsub to ConfigDB at '{}'", settings.url))?;
    let pattern = settings.keyspace_pattern();
    pubsub
        .psubscribe(&pattern)
        .await
        .with_context(|| format!("PSUBSCRIBE {pattern} failed"))?;

    let (tx, rx) = mpsc::channel::<()>(1);
    let debounce = settings.debounce;

    tokio::spawn(async move {
        log::info!("Subscribed to SONiC ConfigDB keyspace notifications: {pattern}");
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            log::debug!("ConfigDB change on channel '{}'", msg.get_channel_name());

            // Debounce: drain any additional events that arrive within the
            // window so we coalesce bursts into one reload.
            if debounce > Duration::ZERO {
                let deadline = tokio::time::sleep(debounce);
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => break,
                        next = stream.next() => {
                            if next.is_none() {
                                break;
                            }
                        }
                    }
                }
            }

            if tx.send(()).await.is_err() {
                log::debug!("ConfigDB change consumer dropped; exiting notifier");
                break;
            }
        }
        log::info!("ConfigDB pubsub stream ended");
    });

    Ok(rx)
}
