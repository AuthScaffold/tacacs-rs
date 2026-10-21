use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum};
use clap::builder::TypedValueParser as _;
use tacacsrs_config::PskDheKeSupportedGroup;
use tacacsrs_config::tacacsrs::ProxyCredentialSource;

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub(crate) enum ServiceMode {
    /// Host only the local client API service.
    ClientApi,

    /// Host only the raw TACACS+ proxy service.
    TacacsProxy,

    /// Host both local client API and raw TACACS+ proxy services.
    Both,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub(crate) enum PskKeyExchange {
    /// Use TLS 1.3 PSK with ephemeral (EC)DHE key exchange.
    #[value(name = "psk-dhe")]
    PskDhe,

    /// Use TLS 1.3 PSK-only key exchange for interoperability.
    #[value(name = "psk-only")]
    PskOnly,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum HostIntegrationMode {
    /// Detect systemd from `NOTIFY_SOCKET`. If it is absent, use no host integration.
    #[default]
    Auto,

    /// Disable all host-specific notifications.
    None,

    /// Require and publish systemd notifications.
    Systemd,
}

fn psk_dhe_ke_supported_group_parser(
) -> impl clap::builder::TypedValueParser<Value = PskDheKeSupportedGroup> {
    clap::builder::PossibleValuesParser::new(PskDheKeSupportedGroup::ALLOWED_VALUES.iter().copied())
        .map(|value| {
            PskDheKeSupportedGroup::from_rfc7951_str(&value)
                .expect("clap accepted only generated PSK-DHE group values")
        })
}

fn proxy_credential_source_parser(
) -> impl clap::builder::TypedValueParser<Value = ProxyCredentialSource> {
    clap::builder::PossibleValuesParser::new(ProxyCredentialSource::ALLOWED_VALUES.iter().copied())
        .map(|value| {
            ProxyCredentialSource::from_rfc7951_str(&value)
                .expect("clap accepted only generated proxy credential-source values")
        })
}

#[allow(clippy::struct_excessive_bools)]
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
    /// Host process-manager integration mode.
    #[arg(long, value_enum, default_value_t)]
    pub(crate) host_integration: HostIntegrationMode,

    /// Path to a YANG JSON configuration file (ietf-system-tacacs-plus).
    #[arg(long, value_name = "FILE", conflicts_with_all = [
        "server_addresses", "shared_secret", "use_tls",
        "client_certificate", "client_key",
        "insecure_disable_certificate_verification",
        "dedicated",
        "sonic", "sonic_redis_url", "sonic_redis_db",
    ])]
    pub(crate) config: Option<PathBuf>,

    /// Optional live YANG JSON file containing a tacacsrs:runtime-policy resource.
    #[arg(long, value_name = "FILE")]
    pub(crate) runtime_policy: Option<PathBuf>,

    /// Publish read-only YANG statistics atomically to this file once per second.
    #[arg(long, value_name = "FILE")]
    pub(crate) statistics_file: Option<PathBuf>,

    /// Register a public HTTP(S) CRL URL for an opaque evidence reference.
    /// Repeat the reference to add issuer CRLs in fetch order. Locations must contain no secrets.
    #[arg(long, value_names = ["REFERENCE", "URL"], num_args = 2, action = clap::ArgAction::Append)]
    pub(crate) http_crl_source: Vec<String>,

    /// Discover CRLs from a DER certificate, limited to this reference's registered URLs.
    #[arg(long, value_names = ["REFERENCE", "CERTIFICATE"], num_args = 2, action = clap::ArgAction::Append, requires = "http_crl_source")]
    pub(crate) http_crl_certificate: Vec<String>,

    /// Query an explicitly authorized OCSP responder for a DER certificate and issuer.
    #[arg(long, value_names = ["REFERENCE", "URL", "CERTIFICATE", "ISSUER"], num_args = 4, action = clap::ArgAction::Append)]
    pub(crate) http_ocsp_source: Vec<String>,

    /// Discover an OCSP responder from a DER certificate under the responder allowlist.
    #[arg(long, value_names = ["REFERENCE", "CERTIFICATE", "ISSUER"], num_args = 3, action = clap::ArgAction::Append, requires = "http_ocsp_allow_url")]
    pub(crate) http_ocsp_certificate: Vec<String>,

    /// Authorize an exact public URL for certificate-driven OCSP discovery.
    #[arg(long, value_name = "URL", requires = "http_ocsp_certificate")]
    pub(crate) http_ocsp_allow_url: Vec<String>,

    /// Startup YANG JSON file containing a tacacsrs:local-services resource.
    #[arg(long, value_name = "FILE", conflicts_with_all = [
        "listen_endpoint", "proxy_endpoint", "service_mode", "socket_mode", "sonic", "proxy_credential_source",
    ])]
    pub(crate) local_services: Option<PathBuf>,

    /// Ordered list of TACACS+ upstream servers. The first server is preferred.
    #[arg(long = "server-addr", conflicts_with_all = ["sonic", "sonic_redis_url", "sonic_redis_db"])]
    pub(crate) server_addresses: Vec<String>,

    /// Get TACACS+ and local forwarder configuration from `SONiC` `ConfigDB`.
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

    /// Local IPC endpoint. Use a Unix domain socket path on Linux (default: /run/tacacs/tacacs.sock).
    #[arg(long)]
    pub(crate) listen_endpoint: Option<String>,

    /// Optional local TACACS+ proxy endpoint. `SONiC` mode loads this from `ConfigDB`.
    #[arg(long)]
    pub(crate) proxy_endpoint: Option<String>,

    /// Shared secret expected from raw TACACS+ proxy clients.
    #[arg(long, value_name = "SECRET", requires = "proxy_endpoint", conflicts_with = "sonic",
        value_parser = clap::builder::NonEmptyStringValueParser::new().map(tacacsrs_secrets::SecretString::new))]
    pub(crate) proxy_shared_secret: Option<tacacsrs_secrets::SecretString>,

    /// Downstream credential source. `SONiC` defaults to `local-proxy-row`.
    #[arg(long, value_parser = proxy_credential_source_parser())]
    pub(crate) proxy_credential_source: Option<ProxyCredentialSource>,

    /// Runtime service mode. `SONiC` mode requires both services.
    #[arg(long, value_enum)]
    pub(crate) service_mode: Option<ServiceMode>,

    /// File mode applied to the Unix domain socket path (octal string, for example 660).
    #[arg(long)]
    pub(crate) socket_mode: Option<String>,

    /// Shared secret for TACACS+ message obfuscation.
    #[arg(short = 'k', long,
        value_parser = clap::builder::StringValueParser::new().map(tacacsrs_secrets::SecretString::new))]
    pub(crate) shared_secret: Option<tacacsrs_secrets::SecretString>,

    /// Use TLS for upstream TACACS+ server connections.
    #[arg(long)]
    pub(crate) use_tls: bool,

    /// Path to a PEM client certificate chain or one DER certificate.
    /// Put the leaf first, followed by intermediates in issuer order. Omit the root.
    #[arg(long, value_name = "FILE", requires = "client_key")]
    pub(crate) client_certificate: Option<String>,

    /// Path to a PEM- or DER-encoded client private key file for TLS authentication.
    #[arg(long, value_name = "FILE", requires = "client_certificate")]
    pub(crate) client_key: Option<String>,

    /// CAUTION: Disable upstream TLS certificate verification.
    /// This option permits server impersonation.
    #[arg(long, requires = "use_tls")]
    pub(crate) insecure_disable_certificate_verification: bool,

    /// Timeout, in seconds, for establishing a new upstream TACACS+ connection.
    #[arg(long, default_value_t = 5)]
    pub(crate) connect_timeout_seconds: u64,

    /// Use a dedicated upstream connection per request instead of TACACS+ single-connection mode.
    #[arg(long, requires = "server_addresses", conflicts_with = "sonic")]
    pub(crate) dedicated: bool,

    /// Number of Tokio worker threads.
    ///
    /// TACACS+ requests are small and I/O bound, so extra workers mainly add
    /// cross-thread task migration. Raise this only for CPU-bound workloads.
    #[arg(long, default_value = "1")]
    pub(crate) worker_threads: NonZeroUsize,

    /// Increase the log level. Repeat up to four times: -v, -vv, -vvv, or -vvvv.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    #[arg(long, value_name = "IDENTITY", requires_all = ["use_tls", "psk_key"], conflicts_with_all = ["client_certificate", "client_key"])]
    pub(crate) psk_identity: Option<String>,

    #[arg(long, value_name = "KEY", requires_all = ["use_tls", "psk_identity"], conflicts_with_all = ["client_certificate", "client_key"],
        value_parser = clap::builder::StringValueParser::new().map(tacacsrs_secrets::SecretString::new))]
    pub(crate) psk_key: Option<tacacsrs_secrets::SecretString>,

    /// TLS 1.3 PSK key-exchange mode.
    #[arg(long, value_enum, requires_all = ["use_tls", "psk_identity", "psk_key"], conflicts_with_all = ["client_certificate", "client_key"])]
    pub(crate) psk_key_exchange: Option<PskKeyExchange>,

    /// Comma-separated TLS 1.3 PSK-DHE groups in preferred order.
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
