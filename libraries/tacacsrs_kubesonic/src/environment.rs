//! Validated, startup-only `AAAAGENT_` inputs.
//!
//! Parsing does not read files, connect to Redis, or change the process environment.
//! Canonical validators own policy and listener constraints.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use serde_json::{json, Map, Value};

use tacacsrs_config::local_services::parse_local_services;
use tacacsrs_config::policy::parse_runtime_policy;
use tacacsrs_config::tacacsrs::{LocalServices, RuntimePolicy};

const PREFIX: &str = "AAAAGENT_";

pub use tacacsrs_config::source::EmptyServerPolicy;

/// Redis and source-observation controls.
#[derive(Debug, Clone)]
pub struct SourceSettings {
    pub socket: PathBuf,
    pub database: i64,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub empty_servers: EmptyServerPolicy,
    pub upstream_timeout_seconds: u16,
    pub single_connection: bool,
    pub debounce: Duration,
    pub max_delay: Duration,
    pub retry_interval: Duration,
    pub reconcile_interval: Duration,
    pub retry_initial: Duration,
    pub retry_max: Duration,
}

/// Authorized mounted credential paths and observation controls.
#[derive(Debug, Clone)]
pub struct CredentialSettings {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub ca_file: PathBuf,
    pub ca_directory: PathBuf,
    pub debounce: Duration,
    pub reconcile_interval: Duration,
    pub max_identity_bytes: u64,
    pub max_ca_file_bytes: u64,
    pub max_trust_bytes: u64,
    pub max_directory_entries: usize,
    pub max_certificates: usize,
}

/// Optional ConfigDB registration controls.
#[derive(Debug, Clone)]
pub struct LoopbackSettings {
    pub enabled: bool,
    pub priority: u16,
    pub retry_interval: Duration,
}

/// Controls that the host consumes before or outside the async runtime.
#[derive(Debug, Clone)]
pub struct ProcessSettings {
    pub worker_threads: NonZeroUsize,
    pub host_integration: String,
    pub statistics_file: Option<PathBuf>,
    pub log_filter: String,
    pub log_style: String,
}

/// Complete validated startup input for the KubeSONiC profile.
#[derive(Debug, Clone)]
pub struct Environment {
    pub source: SourceSettings,
    pub credentials: CredentialSettings,
    pub loopback: LoopbackSettings,
    pub process: ProcessSettings,
    pub local_services: LocalServices,
    pub runtime_policy: RuntimePolicy,
}

struct Inputs(BTreeMap<String, String>);

impl Inputs {
    fn take(&mut self, suffix: &str) -> Option<String> {
        self.0.remove(&format!("{PREFIX}{suffix}"))
    }

    fn text(&mut self, suffix: &str, default: &str) -> anyhow::Result<String> {
        let value = self.take(suffix).unwrap_or_else(|| default.to_owned());
        ensure!(!value.is_empty(), "{PREFIX}{suffix} must not be empty");
        Ok(value)
    }

    fn number(&mut self, suffix: &str, default: u64) -> anyhow::Result<u64> {
        let Some(value) = self.take(suffix) else {
            return Ok(default);
        };
        ensure!(
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
            "{PREFIX}{suffix} must be an unsigned decimal integer"
        );
        value
            .parse()
            .map_err(|_| anyhow::anyhow!("{PREFIX}{suffix} is outside the supported integer range"))
    }

    fn positive(&mut self, suffix: &str, default: u64) -> anyhow::Result<u64> {
        let value = self.number(suffix, default)?;
        ensure!(value > 0, "{PREFIX}{suffix} must be greater than zero");
        Ok(value)
    }

    fn duration(&mut self, suffix: &str, default: u64, millis: bool) -> anyhow::Result<Duration> {
        let value = self.positive(suffix, default)?;
        let duration = if millis {
            Duration::from_millis(value)
        } else {
            Duration::from_secs(value)
        };
        ensure!(
            std::time::Instant::now().checked_add(duration).is_some(),
            "{PREFIX}{suffix} exceeds the clock range"
        );
        Ok(duration)
    }

    fn boolean(&mut self, suffix: &str, default: bool) -> anyhow::Result<bool> {
        match self.take(suffix).as_deref() {
            None => Ok(default),
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            Some(_) => bail!("{PREFIX}{suffix} must be true or false"),
        }
    }

    fn canonical(
        &mut self,
        area: &str,
        object: &mut Map<String, Value>,
        field: &str,
        kind: Kind,
    ) -> anyhow::Result<()> {
        let suffix = format!("{area}_{}", field.replace('-', "_").to_uppercase());
        if !self.0.contains_key(&format!("{PREFIX}{suffix}")) {
            return Ok(());
        }
        let value = match kind {
            Kind::Number => json!(self.number(&suffix, 0)?),
            Kind::Boolean => json!(self.boolean(&suffix, false)?),
            Kind::Text => json!(self.text(&suffix, "")?),
            Kind::Octal => {
                let raw = self.text(&suffix, "")?;
                ensure!(
                    raw.bytes().all(|byte| (b'0'..=b'7').contains(&byte)),
                    "{PREFIX}{suffix} must be an octal permission value"
                );
                json!(u16::from_str_radix(&raw, 8).map_err(|_| anyhow::anyhow!(
                    "{PREFIX}{suffix} is outside the permission range"
                ))?)
            }
        };
        object.insert(field.to_owned(), value);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Number,
    Boolean,
    Text,
    Octal,
}

const POLICY_NUMBERS: &[&str] = &[
    "shutdown-timeout-seconds",
    "source-stale-timeout-seconds",
    "credential-stale-timeout-seconds",
    "credential-refresh-interval-seconds",
    "failover-recovery-interval-seconds",
];
const POLICY_ENUMS: &[&str] = &[
    "client-api-failover-strategy",
    "tacacs-proxy-failover-strategy",
];
const OPERATION_LIMITS: &[&str] = &[
    "request-timeout-seconds",
    "max-body-length",
    "max-concurrent-requests",
];
const CANDIDATE_LIMITS: &[&str] = &[
    "timeout-seconds",
    "max-resolution-requests",
    "max-retained-material-bytes",
];
const SERVICE_FIELDS: &[(&str, Kind)] = &[
    ("client-api-enabled", Kind::Boolean),
    ("client-api-endpoint", Kind::Text),
    ("tacacs-proxy-enabled", Kind::Boolean),
    ("tacacs-proxy-endpoint", Kind::Text),
    ("unix-socket-mode", Kind::Octal),
    ("max-connections", Kind::Number),
    ("max-client-api-streams", Kind::Number),
    ("connection-lifetime-seconds", Kind::Number),
];

impl Environment {
    /// Reads one process-environment snapshot.
    ///
    /// # Errors
    /// Returns an error for invalid names, encodings, values, or combinations.
    pub fn from_process() -> anyhow::Result<Self> {
        let mut values = BTreeMap::new();
        for (name, value) in std::env::vars_os() {
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with(PREFIX) || LEGACY.contains(&name) {
                values.insert(
                    name.to_owned(),
                    value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("{name} must contain valid Unicode"))?,
                );
            }
        }
        Self::parse(values)
    }

    /// Normalizes a captured environment into canonical configuration.
    ///
    /// Unrelated variables are ignored. Renamed application variables are rejected.
    ///
    /// # Errors
    /// Returns an error for invalid values or unsupported application inputs.
    pub fn parse(values: BTreeMap<String, String>) -> anyhow::Result<Self> {
        for legacy in LEGACY {
            ensure!(
                !values.contains_key(*legacy),
                "{legacy} was renamed; use the documented AAAAGENT_ input"
            );
        }
        let mut inputs = Inputs(
            values
                .into_iter()
                .filter(|(key, _)| key.starts_with(PREFIX))
                .collect(),
        );
        let socket = PathBuf::from(inputs.text("CONFIGDB_SOCKET", "/var/run/redis/redis.sock")?);
        ensure!(socket.is_absolute(), "AAAAGENT_CONFIGDB_SOCKET must be absolute");
        let database = i64::try_from(inputs.number("CONFIGDB_DATABASE", 4)?)
            .context("AAAAGENT_CONFIGDB_DATABASE exceeds the database range")?;
        let empty_servers = match inputs
            .text("CONFIGDB_EMPTY_SERVER_POLICY", "retain")?
            .as_str()
        {
            "retain" => EmptyServerPolicy::Retain,
            "clear" => EmptyServerPolicy::Clear,
            _ => bail!("AAAAGENT_CONFIGDB_EMPTY_SERVER_POLICY must be retain or clear"),
        };
        let upstream_timeout_seconds = u16::try_from(
            inputs.positive("UPSTREAM_CONNECT_TIMEOUT_SECONDS", 5)?,
        )
        .context("AAAAGENT_UPSTREAM_CONNECT_TIMEOUT_SECONDS exceeds the server timeout range")?;
        let source = SourceSettings {
            socket,
            database,
            connect_timeout: inputs.duration("CONFIGDB_CONNECT_TIMEOUT_SECONDS", 5, false)?,
            command_timeout: inputs.duration("CONFIGDB_COMMAND_TIMEOUT_SECONDS", 5, false)?,
            empty_servers,
            upstream_timeout_seconds,
            single_connection: inputs.boolean("UPSTREAM_SINGLE_CONNECTION", true)?,
            debounce: inputs.duration("CONFIGDB_WATCH_DEBOUNCE_MILLISECONDS", 500, true)?,
            max_delay: inputs.duration("CONFIGDB_WATCH_MAX_DELAY_MILLISECONDS", 2000, true)?,
            retry_interval: inputs.duration("CONFIGDB_WATCH_RETRY_INTERVAL_SECONDS", 5, false)?,
            reconcile_interval: inputs.duration(
                "CONFIGDB_WATCH_RECONCILE_INTERVAL_SECONDS",
                60,
                false,
            )?,
            retry_initial: inputs.duration("CONFIG_RETRY_INITIAL_MILLISECONDS", 250, true)?,
            retry_max: inputs.duration("CONFIG_RETRY_MAX_MILLISECONDS", 30000, true)?,
        };
        ensure!(
            source.debounce <= source.max_delay,
            "ConfigDB debounce must not exceed the maximum burst delay"
        );
        ensure!(
            source.retry_initial <= source.retry_max,
            "Initial source retry must not exceed the maximum retry"
        );
        let certificate = path(
            &mut inputs,
            "TLS_CLIENT_CERTIFICATE",
            "/run/certificates/kubelet/pki/kubelet-client-current.pem",
        )?;
        let key = path(
            &mut inputs,
            "TLS_CLIENT_KEY",
            certificate
                .to_str()
                .context("Client certificate path is not Unicode")?,
        )?;
        let credentials = CredentialSettings {
            certificate,
            key,
            ca_file: path(&mut inputs, "TLS_CA_FILE", "/etc/ssl/certs/ca-certificates.crt")?,
            ca_directory: path(&mut inputs, "TLS_CA_DIRECTORY", "/etc/ssl/certs")?,
            debounce: inputs.duration("TLS_WATCH_DEBOUNCE_MILLISECONDS", 200, true)?,
            reconcile_interval: inputs.duration(
                "TLS_WATCH_RECONCILE_INTERVAL_SECONDS",
                60,
                false,
            )?,
            max_identity_bytes: inputs.positive("TLS_MAX_IDENTITY_BYTES", 1024 * 1024)?,
            max_ca_file_bytes: inputs.positive("TLS_MAX_CA_FILE_BYTES", 4 * 1024 * 1024)?,
            max_trust_bytes: inputs.positive("TLS_MAX_TRUST_BYTES", 16 * 1024 * 1024)?,
            max_directory_entries: usize::try_from(
                inputs.positive("TLS_MAX_DIRECTORY_ENTRIES", 4096)?,
            )
            .context("Trust directory entry limit exceeds the platform range")?,
            max_certificates: usize::try_from(inputs.positive("TLS_MAX_CERTIFICATES", 4096)?)
                .context("Trust certificate limit exceeds the platform range")?,
        };
        let loopback = LoopbackSettings {
            enabled: inputs.boolean("LOOPBACK_REGISTRATION_ENABLED", false)?,
            priority: u16::try_from(inputs.positive("LOOPBACK_PRIORITY", 64)?)
                .context("Loopback priority exceeds the integer range")?,
            retry_interval: inputs.duration("LOOPBACK_RETRY_INTERVAL_SECONDS", 5, false)?,
        };
        ensure!(loopback.priority <= 64, "AAAAGENT_LOOPBACK_PRIORITY must be in 1..=64");
        let worker_threads = usize::try_from(inputs.positive("PROCESS_WORKER_THREADS", 1)?)
            .context("Worker count exceeds the platform range")?;
        let host_integration = inputs.text("PROCESS_HOST_INTEGRATION", "none")?;
        ensure!(
            ["none", "auto", "systemd"].contains(&host_integration.as_str()),
            "AAAAGENT_PROCESS_HOST_INTEGRATION must be none, auto, or systemd"
        );
        let log_style = inputs.text("LOG_STYLE", "auto")?;
        ensure!(
            ["auto", "always", "never"].contains(&log_style.as_str()),
            "AAAAGENT_LOG_STYLE must be auto, always, or never"
        );
        let statistics_file = inputs
            .take("PROCESS_STATISTICS_FILE")
            .map(|value| {
                let path = PathBuf::from(value);
                ensure!(path.is_absolute(), "AAAAGENT_PROCESS_STATISTICS_FILE must be absolute");
                Ok(path)
            })
            .transpose()?;
        let process = ProcessSettings {
            worker_threads: NonZeroUsize::new(worker_threads)
                .context("Worker count must be nonzero")?,
            host_integration,
            statistics_file,
            log_filter: inputs.text("LOG_FILTER", "info")?,
            log_style,
        };
        let mut services = Map::new();
        services.insert("tacacs-proxy-enabled".into(), json!(true));
        services.insert("tacacs-proxy-endpoint".into(), json!("127.0.0.1:49"));
        services.insert("unix-socket-mode".into(), json!(0o666));
        let explicit_proxy = inputs
            .0
            .contains_key("AAAAGENT_SERVICES_TACACS_PROXY_ENDPOINT");
        for &(field, kind) in SERVICE_FIELDS {
            inputs.canonical("SERVICES", &mut services, field, kind)?;
        }
        if services.get("tacacs-proxy-enabled") == Some(&json!(false)) {
            ensure!(!explicit_proxy, "A disabled proxy must not have an explicit endpoint");
            services.remove("tacacs-proxy-endpoint");
        }
        let local_services = parse_local_services(&serde_json::to_vec(
            &json!({"tacacsrs:local-services": services}),
        )?)
        .map_err(|_| {
            anyhow::anyhow!(
                "AAAAGENT_SERVICES_ inputs violate canonical local-services constraints"
            )
        })?;
        if loopback.enabled {
            let endpoint = local_services
                .tacacs_proxy_endpoint
                .as_deref()
                .and_then(|value| value.parse::<std::net::SocketAddr>().ok());
            ensure!(
                local_services.tacacs_proxy_enabled && endpoint.is_some_and(|endpoint| endpoint.ip() == std::net::Ipv4Addr::LOCALHOST && endpoint.port() != 0),
                "Loopback registration requires an enabled TCP proxy on 127.0.0.1 with a nonzero port"
            );
        }
        let runtime_policy = policy(&mut inputs)?;
        if let Some((name, _)) = inputs.0.first_key_value() {
            bail!("Unknown or renamed application input: {name}");
        }
        Ok(Self {
            source,
            credentials,
            loopback,
            process,
            local_services,
            runtime_policy,
        })
    }
}

fn path(inputs: &mut Inputs, suffix: &str, default: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(inputs.text(suffix, default)?);
    ensure!(path.is_absolute(), "{PREFIX}{suffix} must be absolute");
    Ok(path)
}

fn policy(inputs: &mut Inputs) -> anyhow::Result<RuntimePolicy> {
    let mut policy = Map::new();
    for field in POLICY_NUMBERS {
        inputs.canonical("POLICY", &mut policy, field, Kind::Number)?;
    }
    for field in POLICY_ENUMS {
        inputs.canonical("POLICY", &mut policy, field, Kind::Text)?;
    }
    for (container, fields) in [
        ("candidate-preparation", CANDIDATE_LIMITS),
        ("authentication", OPERATION_LIMITS),
        ("authorization", OPERATION_LIMITS),
        ("accounting", OPERATION_LIMITS),
    ] {
        let mut object = Map::new();
        let area = format!("POLICY_{}", container.replace('-', "_").to_uppercase());
        for field in fields {
            inputs.canonical(&area, &mut object, field, Kind::Number)?;
        }
        if !object.is_empty() {
            policy.insert(container.into(), Value::Object(object));
        }
    }
    parse_runtime_policy(&serde_json::to_vec(&json!({"tacacsrs:runtime-policy": policy}))?).map_err(
        |_| anyhow::anyhow!("AAAAGENT_POLICY_ inputs violate canonical runtime-policy constraints"),
    )
}

const LEGACY: &[&str] = &[
    "AAAAGENT_REDIS_SOCKET",
    "AAAAGENT_CLIENT_CERTIFICATE",
    "AAAAGENT_CLIENT_KEY",
    "AAAAGENT_REGISTER_LOOPBACK",
    "AAAAGENT_EMPTY_SERVER_POLICY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "RUST_LOG",
    "RUST_LOG_STYLE",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(pairs: &[(&str, &str)]) -> anyhow::Result<Environment> {
        Environment::parse(
            pairs
                .iter()
                .map(|(key, value)| (format!("{PREFIX}{key}"), (*value).to_owned()))
                .collect(),
        )
    }

    #[test]
    fn defaults_preserve_profile_and_canonical_absence() {
        let input = parse(&[]).unwrap();
        assert_eq!(input.source.database, 4);
        assert_eq!(input.source.empty_servers, EmptyServerPolicy::Retain);
        assert_eq!(input.credentials.key, input.credentials.certificate);
        assert_eq!(input.local_services.unix_socket_mode, 0o666);
        assert!(
            input.local_services.client_api_enabled && input.local_services.tacacs_proxy_enabled
        );
        assert!(!input.loopback.enabled);
        assert_eq!(input.runtime_policy, RuntimePolicy::default());
        assert_eq!(input.process.worker_threads.get(), 1);
    }

    #[test]
    fn overrides_match_canonical_policy() {
        let input = parse(&[
            ("POLICY_SHUTDOWN_TIMEOUT_SECONDS", "20"),
            ("POLICY_AUTHENTICATION_MAX_CONCURRENT_REQUESTS", "7"),
            ("POLICY_TACACS_PROXY_FAILOVER_STRATEGY", "ordered-safe-retry"),
            ("SERVICES_UNIX_SOCKET_MODE", "0600"),
            ("CONFIG_RETRY_INITIAL_MILLISECONDS", "125"),
        ])
        .unwrap();
        let expected = parse_runtime_policy(br#"{"tacacsrs:runtime-policy":{"shutdown-timeout-seconds":20,"authentication":{"max-concurrent-requests":7},"tacacs-proxy-failover-strategy":"ordered-safe-retry"}}"#).unwrap();
        assert_eq!(input.runtime_policy, expected);
        assert_eq!(input.local_services.unix_socket_mode, 0o600);
        assert_eq!(input.source.retry_initial, Duration::from_millis(125));
    }

    #[test]
    fn rejects_invalid_and_renamed_inputs_without_values() {
        for (key, value) in [
            ("TYPO", "private-sentinel"),
            ("REGISTER_LOOPBACK", "private-sentinel"),
            ("LOOPBACK_REGISTRATION_ENABLED", ""),
            ("LOOPBACK_REGISTRATION_ENABLED", "TRUE"),
            ("POLICY_SHUTDOWN_TIMEOUT_SECONDS", "0"),
            ("POLICY_CLIENT_API_FAILOVER_STRATEGY", "private-sentinel"),
            ("SERVICES_UNIX_SOCKET_MODE", "888"),
            ("PROCESS_WORKER_THREADS", "0"),
            ("TLS_CLIENT_KEY", ""),
        ] {
            let error = parse(&[(key, value)]).unwrap_err();
            assert!(!format!("{error:#}").contains("private-sentinel"));
        }
    }

    #[test]
    fn policy_mapping_covers_every_canonical_leaf() {
        let policy = RuntimePolicy {
            candidate_preparation: Some(Default::default()),
            authentication: Some(Default::default()),
            authorization: Some(Default::default()),
            accounting: Some(Default::default()),
            ..Default::default()
        };
        let mut values = BTreeMap::new();
        fn collect(
            object: &Map<String, Value>,
            prefix: &str,
            values: &mut BTreeMap<String, String>,
        ) {
            for (key, value) in object {
                let name = format!("{prefix}_{}", key.replace('-', "_").to_uppercase());
                if let Value::Object(object) = value {
                    collect(object, &name, values);
                } else {
                    values.insert(
                        name,
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned),
                    );
                }
            }
        }
        collect(
            serde_json::to_value(&policy).unwrap().as_object().unwrap(),
            "AAAAGENT_POLICY",
            &mut values,
        );
        assert_eq!(Environment::parse(values).unwrap().runtime_policy, policy);
    }

    #[test]
    fn service_mapping_covers_every_supported_canonical_leaf() {
        let services = LocalServices {
            tacacs_proxy_enabled: true,
            tacacs_proxy_endpoint: Some("127.0.0.1:5049".into()),
            ..Default::default()
        };
        let mut values = BTreeMap::new();
        for (field, value) in serde_json::to_value(&services)
            .unwrap()
            .as_object()
            .unwrap()
        {
            if field == "proxy-credential-source" || field == "proxy-shared-secret" {
                continue;
            }
            let value = if field == "unix-socket-mode" {
                format!("{:o}", value.as_u64().unwrap())
            } else {
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned)
            };
            values.insert(
                format!("AAAAGENT_SERVICES_{}", field.replace('-', "_").to_uppercase()),
                value,
            );
        }
        assert_eq!(Environment::parse(values).unwrap().local_services, services);
    }
}
