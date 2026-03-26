use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use tacacsrs_agent::{ServiceConfig, TacacsClientService};
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::{ResolvedSecurity, ServerConnectionConfig, TacacsPlusServerType};

#[derive(Debug, Parser)]
#[command(name = "tacacsrs-agentd", version, author)]
#[command(about = "Central TACACS+ client service for local consumers")]
#[command(group(ArgGroup::new("ipc-endpoint").args(["listen_endpoint"])))]
#[command(group(
    ArgGroup::new("config-source")
        .required(true)
        .args(["config", "server_addresses"])
))]
struct Cli {
    /// Path to a YANG JSON configuration file (ietf-system-tacacs-plus).
    #[arg(long, value_name = "FILE", conflicts_with_all = [
        "server_addresses", "shared_secret", "use_tls",
        "client_certificate", "client_key",
        "insecure_disable_certificate_verification",
    ])]
    config: Option<PathBuf>,

    /// Ordered list of TACACS+ upstream servers. The first server is preferred.
    #[arg(long = "server-addr")]
    server_addresses: Vec<String>,

    /// Local IPC endpoint. Use a Unix socket path on Linux (default: /run/tacacs.sock).
    #[arg(long)]
    listen_endpoint: Option<String>,

    /// File mode applied to the Unix domain socket path (octal string, e.g. 660).
    #[cfg(unix)]
    #[arg(long, default_value = "660")]
    socket_mode: String,

    /// Shared secret for TACACS+ message obfuscation.
    #[arg(short = 'k', long)]
    shared_secret: Option<String>,

    /// Use TLS for upstream TACACS+ server connections.
    #[arg(long)]
    use_tls: bool,

    /// Path to client certificate file for TLS authentication.
    #[arg(long, value_name = "FILE", requires = "client_key")]
    client_certificate: Option<String>,

    /// Path to client private key file for TLS authentication.
    #[arg(long, value_name = "FILE", requires = "client_certificate")]
    client_key: Option<String>,

    /// Dangerously disable upstream TLS certificate verification.
    #[arg(long, requires = "use_tls")]
    insecure_disable_certificate_verification: bool,

    /// Timeout, in seconds, for establishing a new upstream TACACS+ connection.
    #[arg(long, default_value_t = 5)]
    connect_timeout_seconds: u64,

    /// Probe interval, in seconds, used when checking whether the preferred server has recovered.
    #[arg(long, default_value_t = 30)]
    preferred_probe_interval_seconds: u64,

    /// Increase verbosity level (-v, -vv, -vvv, -vvvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[cfg(feature = "psk")]
    #[arg(long, value_name = "IDENTITY", requires_all = ["use_tls", "psk_key"], conflicts_with_all = ["client_certificate", "client_key"])]
    psk_identity: Option<String>,

    #[cfg(feature = "psk")]
    #[arg(long, value_name = "KEY", requires_all = ["use_tls", "psk_identity"], conflicts_with_all = ["client_certificate", "client_key"])]
    psk_key: Option<String>,
}

#[cfg(unix)]
fn parse_socket_mode(mode: &str) -> anyhow::Result<u32> {
    u32::from_str_radix(mode, 8).with_context(|| format!("Invalid socket mode: {mode}"))
}

/// Initializes the logger based on verbosity level.
///
/// When built with the `console` feature, the tokio-console tracing
/// subscriber is used instead of `env_logger`, enabling real-time async
/// runtime profiling via the `tokio-console` tool.
#[cfg(feature = "console")]
fn init_logger(_verbose: u8) {
    console_subscriber::init();
}

/// Initializes the logger based on verbosity level.
#[cfg(not(feature = "console"))]
fn init_logger(verbose: u8) {
    let level = match verbose {
        0 => return,
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    if env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .try_init()
        .is_ok()
    {
        log::debug!("Logging initialized at level: {level}");
    }
}

/// Build server list from CLI flags (legacy path, without a config file).
fn servers_from_cli(cli: &Cli) -> anyhow::Result<Vec<ServerConnectionConfig>> {
    let timeout = Duration::from_secs(cli.connect_timeout_seconds);

    let security = if cli.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (cli.psk_identity.as_ref(), cli.psk_key.as_ref())
        {
            return Ok(cli
                .server_addresses
                .iter()
                .enumerate()
                .map(|(i, addr)| {
                    server_from_address(
                        addr,
                        i,
                        timeout,
                        ResolvedSecurity::Psk {
                            identity: psk_identity.clone(),
                            key: psk_key.clone(),
                        },
                    )
                })
                .collect());
        }

        let client_cert_pem = cli
            .client_certificate
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read client certificate: {path}"))
            })
            .transpose()?;
        let client_key_pem = cli
            .client_key
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read client key: {path}"))
            })
            .transpose()?;

        ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem: Vec::new(),
            insecure_disable_certificate_verification: cli
                .insecure_disable_certificate_verification,
        }
    } else {
        ResolvedSecurity::Obfuscation {
            shared_secret: cli.shared_secret.clone(),
        }
    };

    Ok(cli
        .server_addresses
        .iter()
        .enumerate()
        .map(|(i, addr)| server_from_address(addr, i, timeout, security.clone()))
        .collect())
}

fn server_from_address(
    addr: &str,
    index: usize,
    timeout: Duration,
    security: ResolvedSecurity,
) -> ServerConnectionConfig {
    let (host, port) = match addr.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(49)),
        None => (addr.to_owned(), 49),
    };

    ServerConnectionConfig {
        name: format!("server-{index}"),
        server_type: TacacsPlusServerType::all(),
        address: host,
        port,
        security,
        timeout,
        single_connection: false,
        domain_name: None,
        sni_enabled: false,
    }
}

/// Starts the central TACACS+ client service process.
///
/// The service listens on the configured local IPC endpoint, maintains
/// persistent upstream TACACS+ connections with ordered failover, and shuts
/// down gracefully when it receives a termination signal.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);

    let endpoint = cli
        .listen_endpoint
        .as_deref()
        .map(IpcEndpoint::from_str)
        .transpose()?
        .unwrap_or_else(IpcEndpoint::default_local);

    log::info!("IPC endpoint: {endpoint:?}");

    #[cfg(unix)]
    if matches!(endpoint, IpcEndpoint::Tcp(_)) {
        anyhow::bail!("Linux deployments must use a Unix domain socket endpoint");
    }

    let servers = if let Some(ref config_path) = cli.config {
        log::info!("Loading YANG JSON configuration from {}", config_path.display());
        let yang_config = tacacsrs_config::parse_yang_json_file(config_path)
            .with_context(|| format!("Failed to load config from {}", config_path.display()))?;
        tacacsrs_config::to_connection_configs(&yang_config)
            .context("Failed to map YANG config to connection parameters")?
    } else {
        servers_from_cli(&cli)?
    };

    log::info!(
        "Upstream servers: {} configured, probe interval: {}s",
        servers.len(),
        cli.preferred_probe_interval_seconds,
    );
    for server in &servers {
        log::info!(
            "  {} ({}) -> {}:{}",
            server.name,
            match &server.security {
                ResolvedSecurity::Tls { .. } => "TLS",
                ResolvedSecurity::Psk { .. } => "TLS-PSK",
                ResolvedSecurity::Obfuscation { .. } => "obfuscation",
            },
            server.address,
            server.port,
        );
    }

    let service = TacacsClientService::new(ServiceConfig {
        endpoint,
        servers,
        preferred_probe_interval: Duration::from_secs(cli.preferred_probe_interval_seconds),
        #[cfg(unix)]
        socket_mode: parse_socket_mode(&cli.socket_mode)?,
    })
    .context("Failed to build TACACS+ client service configuration")?;

    service.serve().await
}
