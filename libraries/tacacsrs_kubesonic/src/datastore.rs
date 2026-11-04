//! Read-only ConfigDB observations for the KubeSONiC mTLS profile.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{ensure, Context};
use async_trait::async_trait;
use futures_util::{future::BoxFuture, FutureExt, StreamExt};
use redis::IntoConnectionInfo;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use tacacsrs_config::{TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_config::{
    ClientIdentityCertificate, ServerAuthenticationCaCerts, TlsClientClientIdentity,
    TlsClientServerAuthentication,
};
use tacacsrs_config::keystore::EndEntityCertWithKeyCentralKeystoreReference;
use tacacsrs_config::source::{
    ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigDatastore, ConfigDelta,
    ConfigObservation, DatastoreRuntimePolicy, InitialLoadPolicy,
};

use crate::credentials::{CA_REFERENCE, IDENTITY_REFERENCE};
use crate::environment::SourceSettings;

/// One complete ConfigDB server row.
#[derive(Debug)]
pub struct ServerRow {
    pub address: String,
    pub port: Option<String>,
    pub priority: Option<String>,
    pub valid_hash: bool,
}

/// Recognizes loopbacks that cannot be upstreams.
#[must_use]
pub fn is_loopback(address: &str) -> bool {
    let literal = address.split_once('%').map_or(address, |(ip, _)| ip);
    literal.parse::<IpAddr>().map_or_else(
        |_| {
            address
                .trim_end_matches('.')
                .eq_ignore_ascii_case("localhost")
        },
        |ip| ip.to_canonical().is_loopback(),
    )
}

/// Maps vendor rows to canonical TLS servers with provider references.
///
/// # Errors
/// Returns an error for invalid rows or canonical configuration.
pub fn map_rows(rows: Vec<ServerRow>, settings: &SourceSettings) -> anyhow::Result<TacacsPlus> {
    let mut servers = Vec::new();
    for row in rows {
        if is_loopback(&row.address) {
            continue;
        }
        ensure!(row.valid_hash, "ConfigDB upstream row is not a hash");
        let port = decimal(row.port.as_deref(), 49, u16::MAX)?;
        let priority = decimal(row.priority.as_deref(), 1, 64)?;
        let mut server = TacacsPlusServerBuilder::new(
            &row.address,
            TacacsPlusServerType::all(),
            &row.address,
            port,
        )
        .with_timeout(settings.upstream_timeout_seconds)
        .with_single_connection(settings.single_connection)
        .with_tls_server_authentication()
        .build();
        server.client_identity = Some(TlsClientClientIdentity {
            certificate: Some(ClientIdentityCertificate {
                central_keystore_reference: Some(EndEntityCertWithKeyCentralKeystoreReference {
                    asymmetric_key: Some(IDENTITY_REFERENCE.into()),
                    certificate: Some(IDENTITY_REFERENCE.into()),
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
        server.server_authentication = Some(TlsClientServerAuthentication {
            ca_certs: Some(ServerAuthenticationCaCerts {
                central_truststore_reference: Some(CA_REFERENCE.into()),
                ..Default::default()
            }),
            ..Default::default()
        });
        let endpoint = if row.address.contains(':') {
            format!("[{}]:{port}", row.address)
        } else {
            format!("{}:{port}", row.address)
        };
        servers.push((std::cmp::Reverse(priority), endpoint, server));
    }
    servers.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    if servers.is_empty() {
        return Ok(TacacsPlus::empty());
    }
    servers
        .into_iter()
        .fold(TacacsPlusBuilder::new(), |builder, (_, _, server)| builder.with_server(server))
        .build()
}

fn decimal(value: Option<&str>, default: u16, maximum: u16) -> anyhow::Result<u16> {
    let Some(value) = value else {
        return Ok(default);
    };
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "Invalid ConfigDB numeric field"
    );
    let number: u16 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("ConfigDB numeric field exceeds its range"))?;
    ensure!((1..=maximum).contains(&number), "ConfigDB numeric field exceeds its range");
    Ok(number)
}

impl SourceSettings {
    pub(crate) fn client(&self) -> anyhow::Result<redis::Client> {
        let connection = redis::ConnectionAddr::Unix(self.socket.clone())
            .into_connection_info()?
            .set_redis_settings(redis::RedisConnectionInfo::default().set_db(self.database));
        redis::Client::open(connection).context("Invalid ConfigDB connection configuration")
    }

    pub(crate) async fn connect(&self) -> anyhow::Result<redis::aio::MultiplexedConnection> {
        tokio::time::timeout(
            self.connect_timeout,
            self.client()?.get_multiplexed_async_connection(),
        )
        .await
        .context("ConfigDB connection timed out")?
        .context("ConfigDB connection failed")
    }

    async fn snapshot(&self) -> anyhow::Result<TacacsPlus> {
        let mut connection = self.connect().await?;
        let reply: Vec<(String, Option<String>, Option<String>, bool)> = tokio::time::timeout(
            self.command_timeout,
            redis::cmd("EVAL")
                .arg(SNAPSHOT)
                .arg(0)
                .query_async(&mut connection),
        )
        .await
        .context("ConfigDB snapshot timed out")?
        .context("ConfigDB snapshot failed")?;
        map_rows(
            reply
                .into_iter()
                .map(|(key, port, priority, valid_hash)| ServerRow {
                    address: key["TACPLUS_SERVER|".len()..].to_owned(),
                    port,
                    priority,
                    valid_hash,
                })
                .collect(),
            self,
        )
    }
}

// Bound one script's reply and work independently of operator-supplied row fields.
const SNAPSHOT: &str = r"
local cursor = '0'
local rows = {}
local seen = {}
repeat
    local batch = redis.call('SCAN', cursor, 'MATCH', 'TACPLUS_SERVER|*', 'COUNT', 128)
    cursor = batch[1]
    for _, key in ipairs(batch[2]) do
        if not seen[key] then
            seen[key] = true
            if #rows >= 4096 then return redis.error_reply('upstream row limit exceeded') end
            local valid = redis.call('TYPE', key).ok == 'hash'
            local fields = valid and redis.call('HMGET', key, 'tcp_port', 'priority') or {false, false}
            rows[#rows + 1] = {key, fields[1], fields[2], valid and 1 or 0}
        end
    end
until cursor == '0'
return rows
";

/// Read-only KubeSONiC datastore.
pub struct KubeSonicConfigDb {
    settings: SourceSettings,
    policy: DatastoreRuntimePolicy,
}

impl KubeSonicConfigDb {
    /// Creates a source with validated native recovery controls.
    ///
    /// # Errors
    /// Returns an error for invalid retry delays.
    pub fn new(settings: SourceSettings) -> anyhow::Result<Self> {
        let policy = DatastoreRuntimePolicy::new(
            InitialLoadPolicy::RetryUntilAvailable,
            ChangeNotificationMode::Continuous,
        )
        .with_empty_servers(settings.empty_servers)
        .with_retry_backoff(settings.retry_initial, settings.retry_max)?;
        Ok(Self { settings, policy })
    }
}

#[async_trait]
impl ConfigDatastore for KubeSonicConfigDb {
    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        self.policy
    }
    fn label(&self) -> &'static str {
        "kubesonic-configdb"
    }
    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        self.settings.snapshot().await
    }
    async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
        let mut pubsub = tokio::time::timeout(
            self.settings.connect_timeout,
            self.settings.client()?.get_async_pubsub(),
        )
        .await
        .context("ConfigDB subscription connection timed out")??;
        tokio::time::timeout(
            self.settings.command_timeout,
            pubsub.psubscribe(format!("__keyspace@{}__:TACPLUS_SERVER|*", self.settings.database)),
        )
        .await
        .context("ConfigDB subscription timed out")??;
        let (sender, signals) = watch::channel(());
        let pump = tokio::spawn(async move {
            let mut messages = pubsub.on_message();
            loop {
                tokio::select! {
                    biased;
                    () = sender.closed() => break,
                    message = messages.next() => {
                        if message.is_none() { break; }
                        sender.send_replace(());
                    }
                }
            }
        });
        Ok(Box::new(Observation {
            settings: self.settings.clone(),
            signals,
            pump,
            previous: None,
            read: None,
            due: Instant::now(),
            burst: None,
            quiet: None,
        }))
    }
}

struct Observation {
    settings: SourceSettings,
    signals: watch::Receiver<()>,
    pump: JoinHandle<()>,
    previous: Option<Arc<TacacsPlus>>,
    read: Option<BoxFuture<'static, anyhow::Result<TacacsPlus>>>,
    due: Instant,
    burst: Option<Instant>,
    quiet: Option<Instant>,
}

impl Drop for Observation {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

#[async_trait]
impl ConfigObservation for Observation {
    async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
        loop {
            self.signals
                .has_changed()
                .context("ConfigDB subscription disconnected")?;
            if self.read.is_none() {
                let deadline = self.quiet.map_or(self.due, |quiet| quiet.min(self.due));
                tokio::select! {
                    biased;
                    signal = self.signals.changed() => {
                        signal.context("ConfigDB subscription disconnected")?;
                        let now = Instant::now();
                        let start = *self.burst.get_or_insert(now);
                        self.quiet = Some((now + self.settings.debounce).min(start + self.settings.max_delay));
                        continue;
                    }
                    () = tokio::time::sleep_until(deadline) => {}
                }
                self.signals.borrow_and_update();
                self.burst = None;
                self.quiet = None;
                let settings = self.settings.clone();
                self.read = Some(async move { settings.snapshot().await }.boxed());
            }
            let mut connection = self.signals.clone();
            let disconnected = async move { while connection.changed().await.is_ok() {} };
            let read = self.read.as_mut().context("ConfigDB read is missing")?;
            let result = tokio::select! {
                biased;
                () = disconnected => anyhow::bail!("ConfigDB subscription disconnected"),
                result = read => result,
            };
            self.read = None;
            match result {
                Ok(config) => {
                    self.due = Instant::now() + self.settings.reconcile_interval;
                    let config = Arc::new(config);
                    let delta = ConfigDelta::diff(self.previous.as_deref(), &config);
                    self.previous = Some(config.clone());
                    return Ok(Some(ConfigChangeEvent::Changed(ConfigChange { config, delta })));
                }
                Err(_) => {
                    log::warn!(
                        "KubeSONiC ConfigDB snapshot rejected; retaining known-good configuration"
                    );
                    self.due = Instant::now() + self.settings.retry_interval;
                    return Ok(Some(ConfigChangeEvent::CandidateRejected));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use crate::environment::Environment;
    use super::*;

    #[test]
    fn rows_preserve_order_identity_and_profile_references() {
        let settings = Environment::parse(BTreeMap::new()).unwrap().source;
        let row = |address: &str, priority: &str| ServerRow {
            address: address.into(),
            port: None,
            priority: Some(priority.into()),
            valid_hash: true,
        };
        let source = map_rows(
            vec![
                row("192.0.2.2", "1"),
                row("::ffff:127.0.0.1", "64"),
                row("192.0.2.1", "2"),
            ],
            &settings,
        )
        .unwrap();
        assert_eq!(source.server.len(), 2);
        assert_eq!(source.server[0].name, "192.0.2.1");
        assert!(source
            .server
            .iter()
            .all(|server| server.shared_secret.is_none()));
        assert_eq!(map_rows(Vec::new(), &settings).unwrap().server.len(), 0);
        assert!(map_rows(vec![row("192.0.2.1", "0")], &settings).is_err());
    }
}
