use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use tacacsrs_agent::{ServiceConfig, TacacsClientService, UpstreamConnectionOptions};
use tacacsrs_agent_client::IpcEndpoint;

#[derive(Debug, Parser)]
#[command(name = "tacacsrs-agentd", version, author)]
#[command(about = "Central TACACS+ client service for local consumers")]
#[command(group(ArgGroup::new("ipc-endpoint").args(["listen_endpoint"])))]
struct Cli {
    /// Ordered list of TACACS+ upstream servers. The first server is preferred.
    #[arg(long = "server-addr", required = true)]
    server_addresses: Vec<String>,

    /// Local IPC endpoint. Use a Unix socket path on Linux (default: /run/tacacs.sock).
    #[arg(long)]
    listen_endpoint: Option<String>,

    /// File mode applied to the Unix domain socket path (octal string, e.g. 660).
    #[cfg(unix)]
    #[arg(long, default_value = "660")]
    socket_mode: String,

    /// Obfuscation key for TACACS+ messages.
    #[arg(short = 'k', long)]
    obfuscation_key: Option<String>,

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

    log::info!(
        "Upstream servers: {:?}, TLS: {}, connect timeout: {}s, probe interval: {}s",
        cli.server_addresses,
        cli.use_tls,
        cli.connect_timeout_seconds,
        cli.preferred_probe_interval_seconds,
    );

    let service = TacacsClientService::new(ServiceConfig {
        endpoint,
        server_addresses: cli.server_addresses,
        upstream: UpstreamConnectionOptions {
            obfuscation_key: cli.obfuscation_key,
            use_tls: cli.use_tls,
            client_certificate: cli.client_certificate,
            client_key: cli.client_key,
            insecure_disable_certificate_verification: cli
                .insecure_disable_certificate_verification,
            #[cfg(feature = "psk")]
            psk_identity: cli.psk_identity,
            #[cfg(feature = "psk")]
            psk_key: cli.psk_key,
            connect_timeout: Duration::from_secs(cli.connect_timeout_seconds),
        },
        preferred_probe_interval: Duration::from_secs(cli.preferred_probe_interval_seconds),
        #[cfg(unix)]
        socket_mode: parse_socket_mode(&cli.socket_mode)?,
    })
    .context("Failed to build TACACS+ client service configuration")?;

    service.serve().await
}
