use std::path::PathBuf;

use clap::{ArgGroup, Parser};
#[cfg(feature = "psk")]
use clap::ValueEnum;
#[cfg(feature = "psk")]
use clap::builder::TypedValueParser as _;
#[cfg(feature = "psk")]
use tacacsrs_config::PskDheKeSupportedGroup;

#[cfg(feature = "psk")]
#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub(crate) enum PskKeyExchange {
    /// Use TLS 1.3 PSK with ephemeral (EC)DHE key exchange.
    #[value(name = "psk-dhe")]
    PskDhe,

    /// Use TLS 1.3 PSK-only key exchange for interoperability.
    #[value(name = "psk-only")]
    PskOnly,
}

#[cfg(feature = "psk")]
fn psk_dhe_ke_supported_group_parser(
) -> impl clap::builder::TypedValueParser<Value = PskDheKeSupportedGroup> {
    clap::builder::PossibleValuesParser::new(PskDheKeSupportedGroup::ALLOWED_VALUES.iter().copied())
        .map(|value| {
            PskDheKeSupportedGroup::from_rfc7951_str(&value)
                .expect("clap accepted only generated PSK-DHE group values")
        })
}

#[derive(Debug, Parser)]
#[command(name = "tacacsrs-agentd", version, author)]
#[command(about = "Central TACACS+ client service for local consumers")]
#[command(group(ArgGroup::new("ipc-endpoint").args(["listen_endpoint"]))) ]
#[command(group(
    ArgGroup::new("config-source")
        .required(true)
        .args(["config", "server_addresses", "sonic"])
))]
pub(crate) struct Cli {
    /// Path to a YANG JSON configuration file (ietf-system-tacacs-plus).
    #[arg(long, value_name = "FILE", conflicts_with_all = [
        "server_addresses", "shared_secret", "use_tls",
        "client_certificate", "client_key",
        "insecure_disable_certificate_verification",
        "sonic", "sonic_redis_url", "sonic_redis_db",
    ])]
    pub(crate) config: Option<PathBuf>,

    /// Ordered list of TACACS+ upstream servers. The first server is preferred.
    #[arg(long = "server-addr", conflicts_with_all = ["sonic", "sonic_redis_url", "sonic_redis_db"])]
    pub(crate) server_addresses: Vec<String>,

    /// Source TACACS+ configuration from `SONiC` `ConfigDB` (`TACPLUS` /
    /// `TACPLUS_SERVER` Redis tables).
    #[arg(long)]
    pub(crate) sonic: bool,

    /// Override the `SONiC` `ConfigDB` Redis connection URL (default:
    /// `unix:///var/run/redis/redis.sock?db=4`).
    #[arg(long, value_name = "URL", requires = "sonic")]
    pub(crate) sonic_redis_url: Option<String>,

    /// Override the `SONiC` `ConfigDB` Redis database index used for keyspace
    /// notifications (default: `4`).
    #[arg(long, value_name = "INDEX", requires = "sonic")]
    pub(crate) sonic_redis_db: Option<i64>,

    /// Local IPC endpoint. Use a Unix socket path on Linux (default: /run/tacacs/tacacs.sock).
    #[arg(long)]
    pub(crate) listen_endpoint: Option<String>,

    /// File mode applied to the Unix domain socket path (octal string, e.g. 660).
    #[cfg(unix)]
    #[arg(long, default_value = "660")]
    pub(crate) socket_mode: String,

    /// Shared secret for TACACS+ message obfuscation.
    #[arg(short = 'k', long)]
    pub(crate) shared_secret: Option<String>,

    /// Use TLS for upstream TACACS+ server connections.
    #[arg(long)]
    pub(crate) use_tls: bool,

    /// Path to a PEM- or DER-encoded client certificate file for TLS authentication.
    #[arg(long, value_name = "FILE", requires = "client_key")]
    pub(crate) client_certificate: Option<String>,

    /// Path to a PEM- or DER-encoded client private key file for TLS authentication.
    #[arg(long, value_name = "FILE", requires = "client_certificate")]
    pub(crate) client_key: Option<String>,

    /// Dangerously disable upstream TLS certificate verification.
    #[arg(long, requires = "use_tls")]
    pub(crate) insecure_disable_certificate_verification: bool,

    /// Timeout, in seconds, for establishing a new upstream TACACS+ connection.
    #[arg(long, default_value_t = 5)]
    pub(crate) connect_timeout_seconds: u64,

    /// Probe interval, in seconds, used when checking whether the preferred server has recovered.
    #[arg(long, default_value_t = 30)]
    pub(crate) preferred_probe_interval_seconds: u64,

    /// Increase verbosity level (-v, -vv, -vvv, -vvvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    #[cfg(feature = "psk")]
    #[arg(long, value_name = "IDENTITY", requires_all = ["use_tls", "psk_key"], conflicts_with_all = ["client_certificate", "client_key"])]
    pub(crate) psk_identity: Option<String>,

    #[cfg(feature = "psk")]
    #[arg(long, value_name = "KEY", requires_all = ["use_tls", "psk_identity"], conflicts_with_all = ["client_certificate", "client_key"])]
    pub(crate) psk_key: Option<String>,

    /// TLS 1.3 PSK key-exchange mode.
    #[cfg(feature = "psk")]
    #[arg(long, value_enum, requires_all = ["use_tls", "psk_identity", "psk_key"], conflicts_with_all = ["client_certificate", "client_key"])]
    pub(crate) psk_key_exchange: Option<PskKeyExchange>,

    /// Comma-separated TLS 1.3 PSK-DHE groups in preferred order.
    #[cfg(feature = "psk")]
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "GROUP[,GROUP...]",
        value_parser = psk_dhe_ke_supported_group_parser(),
        help = "Comma-separated TLS 1.3 PSK-DHE groups in preferred order",
        requires_all = ["use_tls", "psk_identity", "psk_key"],
        conflicts_with_all = ["client_certificate", "client_key"]
    )]
    pub(crate) psk_key_exchange_groups: Vec<PskDheKeSupportedGroup>,
}
