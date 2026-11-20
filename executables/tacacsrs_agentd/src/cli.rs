use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use clap::{ArgGroup, Args, CommandFactory, FromArgMatches, Parser, ValueEnum};
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
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("ipc-endpoint").args(["listen_endpoint"]))) ]
pub(crate) struct CommonArgs {
    /// Host process-manager integration mode.
    #[arg(long, value_enum, default_value_t)]
    pub(crate) host_integration: HostIntegrationMode,

    /// Path to a YANG JSON configuration file (ietf-system-tacacs-plus).
    #[arg(long, value_name = "FILE", conflicts_with_all = [
        "server_addresses", "shared_secret", "use_tls",
        "client_certificate", "client_key",
        "insecure_disable_certificate_verification",
        "dedicated",
    ])]
    pub(crate) config: Option<PathBuf>,

    /// Optional live YANG JSON file containing a tacacsrs:runtime-policy resource.
    #[arg(long, value_name = "FILE")]
    pub(crate) runtime_policy: Option<PathBuf>,

    /// Publish read-only YANG statistics atomically to this file once per second.
    #[arg(long, value_name = "FILE")]
    pub(crate) statistics_file: Option<PathBuf>,

    /// Send an RFC 8907 accounting WATCHDOG record to the upstream servers at this interval.
    /// A failed probe withdraws readiness until a later probe succeeds. The watchdog is off by default.
    #[arg(long, value_name = "SECONDS")]
    pub(crate) upstream_watchdog_interval_seconds: Option<NonZeroU64>,

    /// Startup YANG JSON file containing a tacacsrs:local-services resource.
    #[arg(long, value_name = "FILE", conflicts_with_all = [
        "listen_endpoint", "proxy_endpoint", "service_mode", "socket_mode", "proxy_credential_source",
    ])]
    pub(crate) local_services: Option<PathBuf>,

    /// Ordered list of TACACS+ upstream servers. The first server is preferred.
    #[arg(long = "server-addr")]
    pub(crate) server_addresses: Vec<String>,

    /// Local IPC endpoint. Use a Unix domain socket path on Linux (default: /run/tacacs/tacacs.sock).
    #[arg(long)]
    pub(crate) listen_endpoint: Option<String>,

    /// Optional local TACACS+ proxy endpoint. `SONiC` mode loads this from `ConfigDB`.
    #[arg(long)]
    pub(crate) proxy_endpoint: Option<String>,

    /// Shared secret expected from raw TACACS+ proxy clients.
    #[arg(long, value_name = "SECRET", requires = "proxy_endpoint",
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
    #[arg(long, requires = "server_addresses")]
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

pub(crate) struct Cli {
    common: CommonArgs,
    pub(crate) matches: clap::ArgMatches,
}

impl std::fmt::Debug for Cli {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.common.fmt(formatter)
    }
}

impl std::ops::Deref for Cli {
    type Target = CommonArgs;
    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl std::ops::DerefMut for Cli {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

macro_rules! source_arguments {
    ($($source:ident => ($selector:literal, $configure:expr)),+ $(,)?) => {
        pub(crate) fn configure_sources(mut command: clap::Command) -> clap::Command {
            $(command = ($configure)(command);)+
            command.group(ArgGroup::new("config-source").required(true).args([$($selector),+]))
        }
    };
}
crate::source_registry::registered_sources!(source_arguments);

impl CommandFactory for Cli {
    fn command() -> clap::Command {
        configure_sources(CommonArgs::augment_args(
            clap::Command::new("tacacsrs-agentd")
                .version(env!("CARGO_PKG_VERSION"))
                .author(env!("CARGO_PKG_AUTHORS"))
                .about("Central TACACS+ client service for local consumers"),
        ))
    }
    fn command_for_update() -> clap::Command {
        Self::command()
    }
}

impl FromArgMatches for Cli {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        Ok(Self {
            common: CommonArgs::from_arg_matches(matches)?,
            matches: matches.clone(),
        })
    }
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        self.common.update_from_arg_matches(matches)?;
        self.matches = matches.clone();
        Ok(())
    }
}

impl Parser for Cli {}
