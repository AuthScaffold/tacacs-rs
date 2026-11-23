//! Read-only ConfigDB observations for the KubeSONiC mTLS profile.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{ensure, Context};
use async_trait::async_trait;
use futures_util::{FutureExt, StreamExt};
use redis::IntoConnectionInfo;

use tacacsrs_config::{TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_config::{
    ClientIdentityCertificate, ServerAuthenticationCaCerts, TlsClientClientIdentity,
    TlsClientServerAuthentication,
};
use tacacsrs_config::keystore::EndEntityCertWithKeyCentralKeystoreReference;
use tacacsrs_config::source::{
    ChangeNotificationMode, ConfigDatastore, ConfigObservation, ObservationSchedule,
    ObservedSnapshot, SignalObservation, SourceBehavior,
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
///
/// The KubeSONiC profile excludes every loopback host, regardless of port.
/// Shared runtime guards also compare destinations with the bound proxy endpoint,
/// including resolved addresses and the connected peer.
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
        ensure!(
            !row.address.trim().is_empty() && row.address.trim() == row.address,
            "Invalid ConfigDB server configuration"
        );
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
    let mut config = if servers.is_empty() {
        TacacsPlus::empty()
    } else {
        servers
            .into_iter()
            .fold(TacacsPlusBuilder::new(), |builder, (_, _, server)| builder.with_server(server))
            .build()
            .context("Invalid ConfigDB server configuration")?
    };
    config
        .certificate_revocation
        .clone_from(&settings.certificate_revocation);
    Ok(config)
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
// The script checks the key and field lengths before it copies the field values.
// SCAN visits every key in the database, so the script cost grows with the whole
// keyspace. Redis serves no other command while the script runs. The observation
// debounces notifications, so a burst of writes causes one scan.
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
            if #key > 512 then return redis.error_reply('upstream key too long') end
            local valid = redis.call('TYPE', key).ok == 'hash'
            if valid and (redis.call('HSTRLEN', key, 'tcp_port') > 16
                or redis.call('HSTRLEN', key, 'priority') > 16) then
                return redis.error_reply('upstream field too long')
            end
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
    policy: SourceBehavior,
}

impl KubeSonicConfigDb {
    /// Creates a source with validated native recovery controls.
    ///
    /// # Errors
    /// Returns an error for invalid retry delays.
    pub fn new(settings: SourceSettings) -> anyhow::Result<Self> {
        let policy = SourceBehavior::new(ChangeNotificationMode::Continuous)
            .with_empty_servers(settings.empty_servers)
            .with_retry_backoff(settings.retry_initial, settings.retry_max)?;
        Ok(Self { settings, policy })
    }
}

#[async_trait]
impl ConfigDatastore for KubeSonicConfigDb {
    fn behavior(&self) -> SourceBehavior {
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
        let settings = self.settings.clone();
        let schedule = ObservationSchedule {
            debounce: settings.debounce,
            max_delay: Some(settings.max_delay),
            reconcile_interval: Some(settings.reconcile_interval),
            retry_interval: Some(settings.retry_interval),
        };
        let notifications = pubsub.into_on_message().map(|_| ());
        Ok(Box::new(SignalObservation::spawn(
            notifications,
            schedule,
            "ConfigDB subscription disconnected",
            move || {
                let settings = settings.clone();
                async move {
                    match settings.snapshot().await {
                        Ok(config) => Ok(ObservedSnapshot::config_only(Arc::new(config))),
                        Err(error) => {
                            let reason = classify_snapshot_error(&error);
                            log::warn!(
                                "KubeSONiC ConfigDB snapshot rejected ({reason}); retaining known-good configuration"
                            );
                            Err(())
                        }
                    }
                }
                .boxed()
            },
        )))
    }
}

/// Maps a snapshot error to a static, secret-free diagnostic category.
fn classify_snapshot_error(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        let message = cause.to_string();
        if message.contains("ConfigDB connection timed out") {
            return "connection timed out";
        }
        if message.contains("ConfigDB connection failed")
            || message.contains("Invalid ConfigDB connection configuration")
        {
            return "connection failed";
        }
        if message.contains("ConfigDB snapshot timed out") {
            return "snapshot timed out";
        }
        if message.contains("upstream row limit exceeded") {
            return "upstream row limit exceeded";
        }
        if message.contains("upstream key too long") || message.contains("upstream field too long")
        {
            return "upstream key or field limit exceeded";
        }
        if message.contains("ConfigDB upstream row is not a hash") {
            return "row is not a hash";
        }
        if message.contains("ConfigDB numeric field") {
            return "invalid numeric field";
        }
        if message.contains("Invalid ConfigDB server configuration") {
            return "invalid server configuration";
        }
    }
    "snapshot query failed"
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use crate::environment::Environment;
    use super::*;

    #[test]
    fn profile_omits_loopback_hosts_on_every_port() {
        let settings = Environment::parse(BTreeMap::new()).unwrap().source;
        for port in ["49", "449"] {
            let rows = [
                "127.0.0.1",
                "127.0.0.2",
                "::1",
                "::ffff:127.0.0.1",
                "LOCALHOST.",
            ]
            .into_iter()
            .chain(["192.0.2.1", "server.example"])
            .map(|address| ServerRow {
                address: address.to_owned(),
                port: Some(port.to_owned()),
                priority: None,
                valid_hash: true,
            })
            .collect();
            let source = map_rows(rows, &settings).unwrap();
            assert_eq!(
                source
                    .server
                    .iter()
                    .map(|server| server.address.as_str())
                    .collect::<Vec<_>>(),
                ["192.0.2.1", "server.example"],
            );
            assert!(source
                .server
                .iter()
                .all(|server| server.port.to_string() == port));
        }
    }

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

    #[test]
    fn every_snapshot_carries_the_revocation_policy() {
        let settings = Environment::parse(BTreeMap::from([
            ("TACACSD_REVOCATION_ENFORCEMENT".to_owned(), "soft-fail".to_owned()),
            (
                "TACACSD_REVOCATION_ALLOWED_DISTRIBUTION_POINTS".to_owned(),
                "http://crl.example/*.crl".to_owned(),
            ),
        ]))
        .unwrap()
        .source;
        let row = ServerRow {
            address: "192.0.2.1".into(),
            port: None,
            priority: None,
            valid_hash: true,
        };
        for rows in [Vec::new(), vec![row]] {
            let source = map_rows(rows, &settings).unwrap();
            assert_eq!(source.certificate_revocation, settings.certificate_revocation);
            assert!(source.certificate_revocation.is_some());
        }
    }

    #[test]
    fn snapshot_error_categories_are_sanitized() {
        let settings = Environment::parse(BTreeMap::new()).unwrap().source;
        let bad_hash = map_rows(
            vec![ServerRow {
                address: "192.0.2.99-secret-sentinel".into(),
                port: None,
                priority: None,
                valid_hash: false,
            }],
            &settings,
        )
        .unwrap_err();
        let bad_port = map_rows(
            vec![ServerRow {
                address: "192.0.2.1".into(),
                port: Some("secret-port-sentinel".into()),
                priority: None,
                valid_hash: true,
            }],
            &settings,
        )
        .unwrap_err();
        let bad_server = map_rows(
            vec![ServerRow {
                address: String::new(),
                port: None,
                priority: None,
                valid_hash: true,
            }],
            &settings,
        )
        .unwrap_err();
        assert_eq!(classify_snapshot_error(&bad_hash), "row is not a hash");
        assert_eq!(classify_snapshot_error(&bad_port), "invalid numeric field");
        assert_eq!(classify_snapshot_error(&bad_server), "invalid server configuration");
    }
}
