use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use tacacsrs_agent::{ServiceConfig, TacacsClientService};
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::{
    TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerExt,
    TacacsPlusServerType,
};
use tacacsrs_networking::helpers::{normalize_cli_certificate_data, normalize_cli_private_key_data};

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

    /// Path to a PEM- or DER-encoded client certificate file for TLS authentication.
    #[arg(long, value_name = "FILE", requires = "client_key")]
    client_certificate: Option<String>,

    /// Path to a PEM- or DER-encoded client private key file for TLS authentication.
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

/// Build the TACACS+ root configuration from CLI flags (legacy path, without a config file).
fn tacacs_plus_from_cli(cli: &Cli) -> anyhow::Result<TacacsPlus> {
    let timeout = u16::try_from(cli.connect_timeout_seconds).unwrap_or(u16::MAX);

    let server_builders: Vec<TacacsPlusServerBuilder> = if cli.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (cli.psk_identity.as_ref(), cli.psk_key.as_ref())
        {
            cli.server_addresses
                .iter()
                .enumerate()
                .map(|(i, addr)| {
                    base_server_builder_from_address(addr, i, timeout)
                        .with_tls13_epsk(psk_identity.clone(), psk_key.as_bytes().to_vec())
                })
                .collect()
        } else {
            tls_cert_server_builders_from_cli(cli, timeout)?
        }
        #[cfg(not(feature = "psk"))]
        {
            tls_cert_server_builders_from_cli(cli, timeout)?
        }
    } else {
        cli.server_addresses
            .iter()
            .enumerate()
            .map(|(i, addr)| match cli.shared_secret.clone() {
                Some(shared_secret) => base_server_builder_from_address(addr, i, timeout)
                    .with_shared_secret(shared_secret),
                None => base_server_builder_from_address(addr, i, timeout),
            })
            .collect()
    };

    server_builders
        .into_iter()
        .fold(TacacsPlusBuilder::new(), TacacsPlusBuilder::with_server_builder)
        .build()
}

/// Build TLS certificate-based server builders from CLI flags.
fn tls_cert_server_builders_from_cli(
    cli: &Cli,
    timeout: u16,
) -> anyhow::Result<Vec<TacacsPlusServerBuilder>> {
    let client_cert_der = cli
        .client_certificate
        .as_ref()
        .map(|path| {
            let cert_data = std::fs::read(path)
                .with_context(|| format!("Failed to read client certificate: {path}"))?;
            normalize_cli_certificate_data(&cert_data)
                .with_context(|| format!("Failed to parse client certificate: {path}"))
        })
        .transpose()?;
    let client_key = cli
        .client_key
        .as_ref()
        .map(|path| {
            let key_data = std::fs::read(path)
                .with_context(|| format!("Failed to read client key: {path}"))?;
            normalize_cli_private_key_data(&key_data)
                .with_context(|| format!("Failed to parse client key: {path}"))
        })
        .transpose()?;

    let (client_key_der, client_key_format) = match client_key {
        Some((der_bytes, private_key_format)) => (Some(der_bytes), Some(private_key_format)),
        None => (None, None),
    };

    Ok(cli
        .server_addresses
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            if client_cert_der.is_some() || client_key_der.is_some() {
                base_server_builder_from_address(addr, i, timeout)
                    .with_tls_client_certificate_with_key_format(
                        client_cert_der.clone(),
                        client_key_der.clone(),
                        client_key_format,
                    )
            } else {
                base_server_builder_from_address(addr, i, timeout).with_tls_server_authentication()
            }
        })
        .collect())
}

fn base_server_builder_from_address(
    addr: &str,
    index: usize,
    timeout: u16,
) -> TacacsPlusServerBuilder {
    let (host, port) = tacacsrs_networking::helpers::parse_host_port(addr, 49);

    TacacsPlusServerBuilder::new(format!("server-{index}"), TacacsPlusServerType::all(), host, port)
        .with_timeout(timeout)
}

fn tacacs_plus_from_config(path: &std::path::Path) -> anyhow::Result<TacacsPlus> {
    tacacsrs_config::parse_yang_json_file(path)
        .with_context(|| format!("Failed to load config from {}", path.display()))
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

    let tacacs_plus = if let Some(ref config_path) = cli.config {
        log::info!("Loading YANG JSON configuration from {}", config_path.display());
        tacacs_plus_from_config(config_path)?
    } else {
        tacacs_plus_from_cli(&cli)?
    };

    log::info!(
        "Upstream servers: {} configured, probe interval: {}s",
        tacacs_plus.server.len(),
        cli.preferred_probe_interval_seconds,
    );
    for server in &tacacs_plus.server {
        let security_label = if server.is_tls() {
            "TLS"
        } else {
            "obfuscation"
        };
        log::info!("  {} ({}) -> {}:{}", server.name, security_label, server.address, server.port);
    }

    let service = TacacsClientService::new(ServiceConfig {
        endpoint,
        tacacs_plus,
        preferred_probe_interval: Duration::from_secs(cli.preferred_probe_interval_seconds),
        #[cfg(unix)]
        socket_mode: parse_socket_mode(&cli.socket_mode)?,
        disable_certificate_verification: cli.insecure_disable_certificate_verification,
    })
    .context("Failed to build TACACS+ client service configuration")?;

    service.serve().await
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{tacacs_plus_from_cli, tacacs_plus_from_config, Cli};
    use tacacsrs_config::crypto_types::PrivateKeyFormat;

    fn sample_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("libraries")
            .join("tacacsrs_networking")
            .join("examples")
            .join("samples")
            .join(file_name)
    }

    fn write_temp_config(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("agentd-config-test-{unique}.json"));
        fs::write(&path, contents).expect("temp config should be written");
        path
    }

    #[test]
    fn tacacs_plus_from_config_loads_all_servers() {
        let path = write_temp_config(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "primary",
                            "server-type": "accounting",
                            "address": "192.0.2.20",
                            "port": 49,
                            "shared-secret": "secret1"
                        },
                        {
                            "name": "secondary",
                            "server-type": "accounting",
                            "address": "192.0.2.21",
                            "port": 49,
                            "shared-secret": "secret2"
                        }
                    ]
                }
            }"#,
        );

        let root = tacacs_plus_from_config(&path).expect("config file should load");
        fs::remove_file(&path).ok();

        assert_eq!(root.server.len(), 2);
        assert_eq!(root.server[0].name, "primary");
        assert_eq!(root.server[1].name, "secondary");
        assert_eq!(root.server[0].shared_secret.as_deref(), Some("secret1"));
    }

    #[test]
    fn tacacs_plus_from_cli_accepts_plain_text_shared_secret() {
        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--shared-secret",
            "secret1",
        ]);

        let root = tacacs_plus_from_cli(&cli).expect("plain-text shared secret should load");
        assert_eq!(root.server[0].shared_secret.as_deref(), Some("secret1"));
    }

    #[test]
    fn tacacs_plus_from_cli_accepts_pem_client_identity_files() {
        let cert_path = sample_path("client.crt");
        let key_path = sample_path("client.key");
        let expected_cert_der =
            fs::read(sample_path("client.crt.der")).expect("sample DER cert exists");
        let expected_key_der =
            fs::read(sample_path("client.key.der")).expect("sample DER key exists");

        let cli = Cli::parse_from([
            "tacacsrs-agentd",
            "--server-addr",
            "192.0.2.20:49",
            "--use-tls",
            "--client-certificate",
            cert_path.to_str().expect("path should be UTF-8"),
            "--client-key",
            key_path.to_str().expect("path should be UTF-8"),
        ]);

        let root = tacacs_plus_from_cli(&cli).expect("PEM client identity should load");
        let inline = root.server[0]
            .client_identity
            .as_ref()
            .and_then(|identity| identity.certificate.as_ref())
            .and_then(|certificate| certificate.inline_definition.as_ref())
            .expect("inline certificate definition should be present");

        assert_eq!(inline.cert_data.as_deref(), Some(expected_cert_der.as_slice()));
        assert_eq!(inline.cleartext_private_key.as_deref(), Some(expected_key_der.as_slice()));
        assert_eq!(inline.private_key_format, Some(PrivateKeyFormat::OneAsymmetricKeyFormat));
    }
}
