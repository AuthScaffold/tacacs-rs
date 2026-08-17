//! Async Redis I/O for SONiC ConfigDB.
//!
//! This module wraps [`redis::aio::MultiplexedConnection`]. It reads the
//! TACACS+ tables in one atomic Redis call. It also provides a Tokio task that
//! subscribes to `__keyspace@<db>__:TACPLUS*` notifications.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use futures_util::StreamExt;
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use tokio::sync::{Notify, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use tacacsrs_credential_resolution::{
    CredentialChangeError, CredentialChangeEvent, CredentialChangeScope, CredentialChangeSource,
    CredentialChangeStream, CredentialKind, CredentialReference,
};

use crate::mapping::{SonicForwarderSettings, SonicHash, SonicTacacsTables};

/// Default Redis URL when the operator does not override it.
///
/// SONiC ships Redis with a Unix domain socket at `/var/run/redis/redis.sock`
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

/// SONiC EPSK file change source that is separate from credential resolution.
#[derive(Debug, Clone)]
pub struct SonicCredentialChangeSource {
    root: PathBuf,
    debounce: Duration,
}

impl SonicCredentialChangeSource {
    /// Creates a change source for one protected EPSK object root.
    #[must_use]
    pub fn new(root: PathBuf, debounce: Duration) -> Self {
        Self { root, debounce }
    }
}

#[async_trait]
impl CredentialChangeSource for SonicCredentialChangeSource {
    async fn subscribe(&self) -> Result<CredentialChangeStream, CredentialChangeError> {
        let receiver = spawn_credential_change_notifier(self.root.clone(), self.debounce)
            .await
            .map_err(|_| CredentialChangeError)?;
        let stream = tokio_stream::once(CredentialChangeEvent::Recovered)
            .chain(ReceiverStream::new(receiver));
        Ok(Box::pin(stream))
    }
}

/// Connection settings for the SONiC ConfigDB Redis instance.
#[derive(Clone)]
pub struct SonicConnection {
    /// Connection string passed to [`redis::Client::open`].
    pub url: String,
    /// Database index that holds CONFIG_DB. SONiC defaults to `4`.
    pub db_index: i64,
    /// Debounce window for keyspace notifications. One reload handles all
    /// changes in this window.
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

// The Redis URL can contain credentials. The watch root is a sensitive path.
// Do not include either value in Debug output.
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
    /// Opens a multiplexed asynchronous connection to ConfigDB.
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
            .with_context(|| format!("failed to select SONiC ConfigDB index {}", self.db_index))?;
        Ok(conn)
    }

    /// Returns the keyspace pattern that covers TACPLUS tables.
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

/// Reads the supported TACACS+ ConfigDB tables in one atomic Redis operation.
///
/// One Lua script reads all rows with `TACPLUS*` prefixes. A concurrent
/// ConfigDB update cannot create a mixed snapshot.
///
/// # Errors
///
/// Returns an error if the script fails or the reply is malformed. Missing
/// tables are valid and produce an empty configuration.
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
/// Rows can contain secret material such as a `passkey`. Errors do not include
/// ConfigDB values. The parser rejects malformed shapes and skips empty hashes.
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

/// Parses a `[key, hash, key, hash, ...]` reply by row address.
///
/// The parser skips empty hashes so a removed key does not create a default row.
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

/// Converts a scalar Redis value into an owned string.
///
/// Errors do not include the value because a row can contain secret material.
fn redis_string(value: redis::Value) -> anyhow::Result<String> {
    match value {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes)
            .map_err(|_| anyhow::anyhow!("ConfigDB value was not valid UTF-8")),
        redis::Value::SimpleString(text) => Ok(text),
        redis::Value::Int(value) => Ok(value.to_string()),
        _ => bail!("ConfigDB value had an unexpected type"),
    }
}

/// Spawns a task that subscribes to TACPLUS keyspace notifications.
///
/// SONiC requires Redis keyspace notifications. Enable them with
/// `CONFIG SET notify-keyspace-events KEA` or an equivalent setting in
/// `/etc/redis/redis.conf`. If notifications are disabled, the task runs but
/// does not send events.
///
/// The receiver yields one signal for each coalesced change window. The task
/// stops when the receiver closes or the Redis connection fails.
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
        log::info!("subscribed to SONiC ConfigDB keyspace notifications: {pattern}");
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            log::debug!("ConfigDB change on channel '{}'", msg.get_channel_name());

            // Drain events during the debounce window. One reload handles the group.
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
/// Returns an error if the root's parent cannot be watched, or if an existing
/// root cannot be watched.
pub async fn spawn_credential_change_notifier(
    root: PathBuf,
    debounce: Duration,
) -> anyhow::Result<mpsc::Receiver<CredentialChangeEvent>> {
    let (event_tx, mut event_rx) = mpsc::channel(32);
    let lost_events = Arc::new(AtomicBool::new(false));
    let refresh_root_watch = Arc::new(AtomicBool::new(false));
    let reconcile = Arc::new(Notify::new());
    let callback_lost_events = Arc::clone(&lost_events);
    let callback_refresh_root_watch = Arc::clone(&refresh_root_watch);
    let callback_reconcile = Arc::clone(&reconcile);
    let callback_root = root.clone();
    let mut watcher = RecommendedWatcher::new(
        move |event| {
            enqueue_credential_event(
                &event_tx,
                &callback_lost_events,
                &callback_refresh_root_watch,
                &callback_reconcile,
                &callback_root,
                event,
            );
        },
        Config::default(),
    )
    .context("create SONiC credential watcher")?;
    if let Some(parent) = root.parent() {
        watcher
            .watch(parent, RecursiveMode::NonRecursive)
            .context("watch SONiC EPSK parent")?;
    }
    if root.exists() {
        watcher
            .watch(&root, RecursiveMode::NonRecursive)
            .context("watch SONiC EPSK root")?;
    }

    let (signal_tx, signal_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        loop {
            let scope = tokio::select! {
                event = event_rx.recv() => {
                    let Some(event) = event else {
                        break;
                    };
                    credential_change_scope(event, &root)
                }
                () = reconcile.notified() => Some(CredentialChangeScope::Unknown),
            };
            if scope.is_none()
                && !lost_events.load(Ordering::Acquire)
                && !refresh_root_watch.load(Ordering::Acquire)
            {
                continue;
            }
            let mut scope = scope.unwrap_or(CredentialChangeScope::Unknown);
            if debounce > Duration::ZERO {
                tokio::time::sleep(debounce).await;
            }
            while let Ok(event) = event_rx.try_recv() {
                if let Some(next_scope) = credential_change_scope(event, &root) {
                    scope = merge_credential_change_scopes(scope, &next_scope);
                }
            }
            if lost_events.swap(false, Ordering::AcqRel) {
                scope = CredentialChangeScope::Unknown;
            }
            if refresh_root_watch.swap(false, Ordering::AcqRel) {
                let _ = watcher.unwatch(&root);
                if root.exists() && watcher.watch(&root, RecursiveMode::NonRecursive).is_err() {
                    log::warn!("failed to register the SONiC EPSK root watch again");
                }
                scope = CredentialChangeScope::Unknown;
            }
            if signal_tx
                .send(CredentialChangeEvent::Changed(scope))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    Ok(signal_rx)
}

fn enqueue_credential_event(
    event_tx: &mpsc::Sender<notify::Result<Event>>,
    lost_events: &AtomicBool,
    refresh_root_watch: &AtomicBool,
    reconcile: &Notify,
    root: &Path,
    event: notify::Result<Event>,
) {
    if event_affects_root_watch(&event, root) {
        refresh_root_watch.store(true, Ordering::Release);
    }
    match event_tx.try_send(event) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            lost_events.store(true, Ordering::Release);
            reconcile.notify_one();
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            log::debug!("SONiC credential watcher consumer dropped");
        }
    }
}

fn event_affects_root_watch(event: &notify::Result<Event>, root: &Path) -> bool {
    match event {
        Ok(event) => event.paths.iter().any(|path| path == root),
        Err(_) => true,
    }
}

fn credential_change_scope(
    event: notify::Result<Event>,
    root: &Path,
) -> Option<CredentialChangeScope> {
    let Ok(event) = event else {
        return Some(CredentialChangeScope::Unknown);
    };
    if matches!(event.kind, EventKind::Access(_)) {
        return None;
    }
    let mut references = std::collections::BTreeSet::new();
    for path in &event.paths {
        if path == root {
            return Some(CredentialChangeScope::Unknown);
        }
        if path.parent() != Some(root) {
            continue;
        }
        let Some(reference) = path.file_name().and_then(|name| name.to_str()) else {
            return Some(CredentialChangeScope::Unknown);
        };
        if is_opaque_object_id(reference) {
            references.insert(reference.to_owned());
        }
    }
    match references.len() {
        0 => None,
        1 => Some(CredentialChangeScope::Known {
            kind: CredentialKind::SymmetricKey,
            reference: CredentialReference::SymmetricKey(
                references.into_iter().next().expect("one reference"),
            ),
        }),
        _ => Some(CredentialChangeScope::Unknown),
    }
}

fn merge_credential_change_scopes(
    current: CredentialChangeScope,
    next: &CredentialChangeScope,
) -> CredentialChangeScope {
    if &current == next {
        current
    } else {
        CredentialChangeScope::Unknown
    }
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

    #[tokio::test]
    async fn saturated_credential_event_queue_requests_unknown_root_reconciliation() {
        let root = PathBuf::from("/reviewed/epsk");
        let (event_tx, _event_rx) = mpsc::channel(1);
        event_tx
            .try_send(Ok(event(EventKind::Modify(ModifyKind::Any), "/reviewed/epsk/object-1")))
            .expect("fill event queue");
        let lost_events = AtomicBool::new(false);
        let refresh_root_watch = AtomicBool::new(false);
        let reconcile = Notify::new();

        enqueue_credential_event(
            &event_tx,
            &lost_events,
            &refresh_root_watch,
            &reconcile,
            &root,
            Ok(event(EventKind::Modify(ModifyKind::Any), "/reviewed/epsk")),
        );

        reconcile.notified().await;
        assert!(lost_events.load(Ordering::Acquire));
        assert!(refresh_root_watch.load(Ordering::Acquire));
    }

    #[test]
    fn credential_event_scope_identifies_objects_and_widens_root_replacement() {
        let root = Path::new("/credentials/epsk");
        let known = credential_change_scope(
            Ok(event(
                EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
                "/credentials/epsk/object-1",
            )),
            root,
        );
        assert_eq!(
            known,
            Some(CredentialChangeScope::Known {
                kind: CredentialKind::SymmetricKey,
                reference: CredentialReference::SymmetricKey("object-1".to_owned()),
            }),
        );
        assert_eq!(
            credential_change_scope(
                Ok(event(EventKind::Modify(ModifyKind::Any), "/credentials/epsk")),
                root,
            ),
            Some(CredentialChangeScope::Unknown),
        );
        assert_eq!(
            credential_change_scope(
                Ok(event(EventKind::Modify(ModifyKind::Any), "/credentials/epsk/.object-1.tmp",)),
                root,
            ),
            None,
        );
        assert_eq!(
            credential_change_scope(
                Ok(event(EventKind::Access(AccessKind::Any), "/credentials/epsk/object-1",)),
                root,
            ),
            None,
        );
        assert_eq!(
            credential_change_scope(Err(notify::Error::generic("watch failure")), root),
            Some(CredentialChangeScope::Unknown),
        );
        assert_eq!(
            merge_credential_change_scopes(
                CredentialChangeScope::Known {
                    kind: CredentialKind::SymmetricKey,
                    reference: CredentialReference::SymmetricKey("object-1".to_owned()),
                },
                &CredentialChangeScope::Known {
                    kind: CredentialKind::SymmetricKey,
                    reference: CredentialReference::SymmetricKey("object-2".to_owned()),
                },
            ),
            CredentialChangeScope::Unknown,
        );
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
        // Skip a discovered key with an empty hash.
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
