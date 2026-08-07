//! Async Redis I/O for SONiC ConfigDB.
//!
//! This module is a thin wrapper around [`redis::aio::MultiplexedConnection`]
//! that reads the TACACS+ tables in a single call (`HGETALL` per table key,
//! preceded by a `KEYS` scan) and exposes a Tokio task that subscribes to
//! Redis keyspace notifications on `__keyspace@<db>__:TACPLUS*`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use futures_util::StreamExt;
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use tokio::sync::mpsc;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::mapping::{SonicForwarderSettings, SonicHash, SonicTacacsTables};

/// Default Redis URL when the operator does not override it.
///
/// SONiC ships Redis with a Unix-domain socket at `/var/run/redis/redis.sock`
/// and uses database index `4` for `CONFIG_DB`.
pub const DEFAULT_REDIS_URL: &str = "unix:///var/run/redis/redis.sock?db=4";

/// CONFIG_DB key prefix for the per-server table.
pub const TACPLUS_SERVER_TABLE: &str = "TACPLUS_SERVER";

/// CONFIG_DB key prefix for the global table.
pub const TACPLUS_GLOBAL_TABLE: &str = "TACPLUS";

/// CONFIG_DB key prefix for TLS 1.3 EPSK upstream servers.
pub const TACPLUS_SERVER_TLS_TABLE: &str = "TACPLUS_SERVER_TLS";

/// CONFIG_DB key for central-agent bind-time settings.
pub const TACPLUS_FORWARDER_TABLE: &str = "TACPLUS_FORWARDER";

/// Connection settings for the SONiC ConfigDB Redis instance.
#[derive(Clone)]
pub struct SonicConnection {
    /// Connection string passed to [`redis::Client::open`].
    pub url: String,
    /// Database index that holds CONFIG_DB. SONiC defaults to `4`.
    pub db_index: i64,
    /// Debounce window applied to keyspace notifications. Multiple changes
    /// arriving within this window are coalesced into a single reload.
    pub debounce: Duration,
    /// EPSK root watched for same-ID atomic replacement.
    pub credential_watch_root: Option<PathBuf>,
}

impl Default for SonicConnection {
    fn default() -> Self {
        Self {
            url: DEFAULT_REDIS_URL.to_string(),
            db_index: 4,
            debounce: Duration::from_millis(250),
            credential_watch_root: Some(PathBuf::from(
                crate::SonicCredentialRoots::DEFAULT_EPSK_ROOT,
            )),
        }
    }
}

// The Redis URL can carry credentials and the watch root is an on-disk secret path; keep both out of Debug.
impl fmt::Debug for SonicConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SonicConnection")
            .field("url", &"<redacted>")
            .field("db_index", &self.db_index)
            .field("debounce", &self.debounce)
            .field(
                "credential_watch_root",
                &self.credential_watch_root.as_ref().map(|_| "<redacted>"),
            )
            .finish()
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
            .context("invalid SONiC ConfigDB Redis connection string")?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .context("failed to connect to SONiC ConfigDB")?;
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

    /// Loads validated bind-time forwarder settings before listener creation.
    ///
    /// # Errors
    ///
    /// Returns an error when ConfigDB is unavailable or the global forwarder
    /// row is missing or invalid.
    pub async fn load_forwarder_settings(&self) -> anyhow::Result<SonicForwarderSettings> {
        let mut connection = self.connect().await?;
        read_forwarder_settings(&mut connection)
            .await?
            .ok_or_else(|| anyhow::anyhow!("TACPLUS_FORWARDER|global is required"))
    }
}

async fn read_forwarder_settings(
    conn: &mut MultiplexedConnection,
) -> anyhow::Result<Option<SonicForwarderSettings>> {
    let key = format!("{TACPLUS_FORWARDER_TABLE}|global");
    let fields: SonicHash = conn
        .hgetall(&key)
        .await
        .with_context(|| format!("HGETALL failed for {key}"))?;
    SonicForwarderSettings::from_hash(&fields)
}

/// Reads the reviewed TACACS+ ConfigDB tables in one atomic, point-in-time
/// server-side execution.
///
/// A single Lua script enumerates only the `TACPLUS*` prefixes and reads every
/// row so a concurrent ConfigDB mutation cannot produce a torn or hybrid
/// snapshot the way separate `KEYS` + per-key `HGETALL` calls could.
///
/// # Errors
///
/// Returns an error if the script fails or the reply is malformed. Missing
/// tables are not an error — the caller decides whether an empty snapshot
/// should be rejected (the mapping function rejects it by default).
pub async fn read_tacacs_tables(
    conn: &mut MultiplexedConnection,
) -> anyhow::Result<SonicTacacsTables> {
    let reply: redis::Value = redis::cmd("EVAL")
        .arg(TACACS_SNAPSHOT_SCRIPT)
        .arg(0)
        .arg(TACPLUS_GLOBAL_TABLE)
        .arg(TACPLUS_FORWARDER_TABLE)
        .arg(TACPLUS_SERVER_TABLE)
        .arg(TACPLUS_SERVER_TLS_TABLE)
        .query_async(conn)
        .await
        .context("atomic ConfigDB TACACS+ snapshot failed")?;
    parse_snapshot(reply)
}

/// Reads the four TACACS+ tables in one atomic execution and returns
/// `[global, forwarder, [key, hash, ...], [key, hash, ...]]`.
const TACACS_SNAPSHOT_SCRIPT: &str = r"
local function collect(prefix)
    local rows = {}
    local keys = redis.call('KEYS', prefix .. '|*')
    for i = 1, #keys do
        rows[#rows + 1] = keys[i]
        rows[#rows + 1] = redis.call('HGETALL', keys[i])
    end
    return rows
end
return {
    redis.call('HGETALL', ARGV[1] .. '|global'),
    redis.call('HGETALL', ARGV[2] .. '|global'),
    collect(ARGV[3]),
    collect(ARGV[4]),
}
";

/// Parses the atomic snapshot reply into typed tables.
///
/// Rows can carry secret material (for example a `passkey`), so errors never
/// echo any ConfigDB value. Malformed shapes are rejected and a row whose hash
/// is empty is skipped rather than materialized as a phantom default.
fn parse_snapshot(reply: redis::Value) -> anyhow::Result<SonicTacacsTables> {
    let redis::Value::Array(mut sections) = reply else {
        bail!("ConfigDB snapshot reply was not an array");
    };
    if sections.len() != 4 {
        bail!("ConfigDB snapshot reply had an unexpected number of sections");
    }
    let tls_servers =
        parse_keyed_hashes(sections.pop().expect("tls section present"), TACPLUS_SERVER_TLS_TABLE)?;
    let servers =
        parse_keyed_hashes(sections.pop().expect("server section present"), TACPLUS_SERVER_TABLE)?;
    let forwarder = parse_hash(sections.pop().expect("forwarder section present"))?;
    let global = parse_hash(sections.pop().expect("global section present"))?;
    Ok(SonicTacacsTables::with_extended_tables(global, servers, tls_servers, forwarder))
}

/// Parses an `HGETALL` reply (`[field, value, ...]`) into a hash.
fn parse_hash(value: redis::Value) -> anyhow::Result<SonicHash> {
    let items = match value {
        redis::Value::Nil => return Ok(SonicHash::new()),
        redis::Value::Array(items) => items,
        redis::Value::Map(pairs) => {
            let mut hash = SonicHash::new();
            for (field, value) in pairs {
                hash.insert(redis_string(field)?, redis_string(value)?);
            }
            return Ok(hash);
        }
        _ => bail!("ConfigDB hash section had an unexpected shape"),
    };
    if items.len() % 2 != 0 {
        bail!("ConfigDB hash section had an odd number of elements");
    }
    let mut hash = SonicHash::new();
    let mut iter = items.into_iter();
    while let (Some(field), Some(value)) = (iter.next(), iter.next()) {
        hash.insert(redis_string(field)?, redis_string(value)?);
    }
    Ok(hash)
}

/// Parses a `[key, hash, key, hash, ...]` reply keyed by the address portion of
/// each row, skipping rows whose hash is empty so a vanished key is never
/// materialized as a phantom default.
fn parse_keyed_hashes(
    value: redis::Value,
    prefix: &str,
) -> anyhow::Result<BTreeMap<String, SonicHash>> {
    let items = match value {
        redis::Value::Nil => return Ok(BTreeMap::new()),
        redis::Value::Array(items) => items,
        _ => bail!("ConfigDB server section had an unexpected shape"),
    };
    if items.len() % 2 != 0 {
        bail!("ConfigDB server section had an odd number of elements");
    }
    let key_prefix = format!("{prefix}|");
    let mut rows = BTreeMap::new();
    let mut iter = items.into_iter();
    while let (Some(key), Some(hash)) = (iter.next(), iter.next()) {
        let key = redis_string(key)?;
        let Some(address) = key.strip_prefix(&key_prefix) else {
            continue;
        };
        let fields = parse_hash(hash)?;
        if fields.is_empty() {
            continue;
        }
        rows.insert(address.to_string(), fields);
    }
    Ok(rows)
}

/// Converts a scalar Redis value into an owned string without echoing the value
/// on error, since a row may carry secret material.
fn redis_string(value: redis::Value) -> anyhow::Result<String> {
    match value {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes)
            .map_err(|_| anyhow::anyhow!("ConfigDB value was not valid UTF-8")),
        redis::Value::SimpleString(text) => Ok(text),
        redis::Value::Int(value) => Ok(value.to_string()),
        _ => bail!("ConfigDB value had an unexpected type"),
    }
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
        .context("invalid SONiC ConfigDB Redis connection string")?;
    let mut pubsub = client
        .get_async_pubsub()
        .await
        .context("failed to open SONiC ConfigDB keyspace subscription")?;
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

/// Watches the reviewed EPSK root and emits debounced complete-reload signals.
///
/// # Errors
///
/// Returns an error if the root or its parent cannot be watched.
pub async fn spawn_credential_change_notifier(
    root: PathBuf,
    debounce: Duration,
) -> anyhow::Result<mpsc::Receiver<()>> {
    let (event_tx, mut event_rx) = mpsc::channel(32);
    let mut watcher = RecommendedWatcher::new(
        move |event| {
            if event_tx.blocking_send(event).is_err() {
                log::debug!("SONiC credential watcher consumer dropped");
            }
        },
        Config::default(),
    )
    .context("create SONiC credential watcher")?;
    watcher
        .watch(&root, RecursiveMode::NonRecursive)
        .context("watch SONiC EPSK root")?;
    if let Some(parent) = root.parent() {
        watcher
            .watch(parent, RecursiveMode::NonRecursive)
            .context("watch SONiC EPSK parent")?;
    }

    let (signal_tx, signal_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let _watcher = watcher;
        while let Some(event) = event_rx.recv().await {
            let relevant = match event {
                Ok(event) => event_touches_credential_object(&event, &root),
                Err(_) => true,
            };
            if !relevant {
                continue;
            }
            if debounce > Duration::ZERO {
                tokio::time::sleep(debounce).await;
            }
            while event_rx.try_recv().is_ok() {}
            if signal_tx.send(()).await.is_err() {
                break;
            }
        }
    });
    Ok(signal_rx)
}

fn event_touches_credential_object(event: &Event, root: &Path) -> bool {
    if matches!(event.kind, EventKind::Access(_)) {
        return false;
    }
    event.paths.iter().any(|path| {
        if path == root {
            return true;
        }
        path.parent() == Some(root)
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(is_opaque_object_id)
    })
}

fn is_opaque_object_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= 64
        && first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use notify::event::{AccessKind, EventAttributes, ModifyKind};
    use redis::Value;

    use super::*;

    fn event(kind: EventKind, path: &str) -> Event {
        Event {
            kind,
            paths: vec![PathBuf::from(path)],
            attrs: EventAttributes::default(),
        }
    }

    #[test]
    fn credential_event_filter_accepts_objects_and_root_but_ignores_temporary_and_access() {
        let root = Path::new("/credentials/epsk");
        assert!(event_touches_credential_object(
            &event(
                EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
                "/credentials/epsk/object-1"
            ),
            root,
        ));
        assert!(event_touches_credential_object(
            &event(EventKind::Modify(ModifyKind::Any), "/credentials/epsk"),
            root,
        ));
        assert!(!event_touches_credential_object(
            &event(EventKind::Modify(ModifyKind::Any), "/credentials/epsk/.object-1.tmp"),
            root,
        ));
        assert!(!event_touches_credential_object(
            &event(EventKind::Access(AccessKind::Any), "/credentials/epsk/object-1"),
            root,
        ));
    }

    #[test]
    fn opaque_object_filter_matches_reviewed_grammar() {
        for valid in ["a", "A1", "object-1", "object_1"] {
            assert!(is_opaque_object_id(valid));
        }
        for invalid in ["", "_object", "-object", ".tmp", "a/b", "../a"] {
            assert!(!is_opaque_object_id(invalid));
        }
    }

    const SENTINEL_USER: &str = "sentineluser";
    const SENTINEL_PASS: &str = "sentinelpassword";
    const SENTINEL_QUERY: &str = "sentinelquery";
    const SENTINEL_WATCH_ROOT: &str = "sentinelwatchroot";

    fn connection_with_url(url: &str) -> SonicConnection {
        SonicConnection {
            url: url.to_owned(),
            db_index: 4,
            debounce: Duration::from_millis(0),
            credential_watch_root: Some(PathBuf::from(format!("/var/lib/{SENTINEL_WATCH_ROOT}"))),
        }
    }

    fn assert_no_sensitive_material(rendered: &str) {
        for forbidden in [
            SENTINEL_USER,
            SENTINEL_PASS,
            SENTINEL_QUERY,
            SENTINEL_WATCH_ROOT,
        ] {
            assert!(
                !rendered.contains(forbidden),
                "sensitive material '{forbidden}' leaked into: {rendered}"
            );
        }
    }

    fn assert_error_is_sanitized(error: &anyhow::Error) {
        for rendered in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert_no_sensitive_material(&rendered);
        }
    }

    #[test]
    fn debug_redacts_url_and_credential_watch_root() {
        let connection = connection_with_url(&format!(
            "redis://{SENTINEL_USER}:{SENTINEL_PASS}@127.0.0.1:6379/0?x={SENTINEL_QUERY}"
        ));
        for rendered in [format!("{connection:?}"), format!("{connection:#?}")] {
            assert_no_sensitive_material(&rendered);
            assert!(rendered.contains("<redacted>"), "expected redaction marker: {rendered}");
            assert!(rendered.contains("db_index"), "expected safe field retained: {rendered}");
        }
    }

    #[tokio::test]
    async fn connect_error_is_sanitized_for_malformed_and_unreachable_urls() {
        let malformed = connection_with_url(&format!(
            "http://{SENTINEL_USER}:{SENTINEL_PASS}@malformed.invalid/?x={SENTINEL_QUERY}"
        ));
        let error = malformed
            .connect()
            .await
            .expect_err("a non-redis scheme must fail to open");
        assert_error_is_sanitized(&error);

        let unreachable =
            connection_with_url(&format!("redis://{SENTINEL_USER}:{SENTINEL_PASS}@127.0.0.1:9/0"));
        let error = unreachable
            .connect()
            .await
            .expect_err("an unreachable endpoint must fail to connect");
        assert_error_is_sanitized(&error);
    }

    #[tokio::test]
    async fn change_notifier_error_is_sanitized_for_malformed_and_unreachable_urls() {
        let malformed = connection_with_url(&format!(
            "http://{SENTINEL_USER}:{SENTINEL_PASS}@malformed.invalid/?x={SENTINEL_QUERY}"
        ));
        let error = spawn_change_notifier(malformed)
            .await
            .expect_err("a non-redis scheme must fail to open");
        assert_error_is_sanitized(&error);

        let unreachable =
            connection_with_url(&format!("redis://{SENTINEL_USER}:{SENTINEL_PASS}@127.0.0.1:9/0"));
        let error = spawn_change_notifier(unreachable)
            .await
            .expect_err("an unreachable endpoint must fail to subscribe");
        assert_error_is_sanitized(&error);
    }

    fn bulk(text: &str) -> Value {
        Value::BulkString(text.as_bytes().to_vec())
    }

    fn hgetall(pairs: &[(&str, &str)]) -> Value {
        let mut items = Vec::new();
        for (field, value) in pairs {
            items.push(bulk(field));
            items.push(bulk(value));
        }
        Value::Array(items)
    }

    #[test]
    fn parse_snapshot_maps_a_complete_generation() {
        let reply = Value::Array(vec![
            hgetall(&[("passkey", "global-secret"), ("timeout", "5")]),
            hgetall(&[("src_ip", "127.0.0.1")]),
            Value::Array(vec![
                bulk("TACPLUS_SERVER|10.0.0.1"),
                hgetall(&[("priority", "1")]),
            ]),
            Value::Array(vec![
                bulk("TACPLUS_SERVER_TLS|10.0.0.2"),
                hgetall(&[("priority", "2"), ("psk_identity", "client")]),
            ]),
        ]);

        let tables = parse_snapshot(reply).expect("well-formed snapshot parses");

        assert_eq!(tables.global.get("timeout").map(String::as_str), Some("5"));
        assert_eq!(tables.forwarder.get("src_ip").map(String::as_str), Some("127.0.0.1"));
        assert!(tables.servers.contains_key("10.0.0.1"));
        assert_eq!(
            tables
                .tls_servers
                .get("10.0.0.2")
                .and_then(|row| row.get("psk_identity")),
            Some(&"client".to_owned())
        );
    }

    #[test]
    fn parse_snapshot_skips_a_row_whose_hash_is_empty() {
        // A discovered key with an empty hash must never become a phantom default row.
        let reply = Value::Array(vec![
            Value::Array(vec![]),
            Value::Array(vec![]),
            Value::Array(vec![bulk("TACPLUS_SERVER|10.0.0.9"), Value::Array(vec![])]),
            Value::Array(vec![]),
        ]);

        let tables = parse_snapshot(reply).expect("snapshot parses");

        assert!(tables.servers.is_empty(), "an empty-hash row must be skipped");
        assert!(tables.is_empty());
    }

    #[test]
    fn parse_snapshot_treats_nil_sections_as_empty() {
        let reply = Value::Array(vec![Value::Nil, Value::Nil, Value::Nil, Value::Nil]);

        let tables = parse_snapshot(reply).expect("nil sections parse as empty");

        assert!(tables.is_empty());
    }

    #[test]
    fn parse_snapshot_rejects_malformed_replies() {
        assert!(parse_snapshot(Value::Okay).is_err(), "a non-array reply must be rejected");
        assert!(
            parse_snapshot(Value::Array(vec![Value::Nil, Value::Nil])).is_err(),
            "the wrong number of sections must be rejected"
        );
        let odd_hash = Value::Array(vec![
            Value::Array(vec![bulk("lonely-field")]),
            Value::Array(vec![]),
            Value::Array(vec![]),
            Value::Array(vec![]),
        ]);
        assert!(parse_snapshot(odd_hash).is_err(), "an odd-length hash must be rejected");
    }
}
