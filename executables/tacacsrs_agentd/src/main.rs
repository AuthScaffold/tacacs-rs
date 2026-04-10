use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use tacacsrs_agent::{ServiceConfig, TacacsClientService};
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::{ResolvedServer, TacacsPlusServer, TacacsPlusServerType};

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
fn servers_from_cli(cli: &Cli) -> anyhow::Result<Vec<ResolvedServer>> {
    let timeout = u16::try_from(cli.connect_timeout_seconds).unwrap_or(u16::MAX);

    if cli.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (cli.psk_identity.as_ref(), cli.psk_key.as_ref())
        {
            return Ok(cli
                .server_addresses
                .iter()
                .enumerate()
                .map(|(i, addr)| {
                    let mut server = base_server_from_address(addr, i, timeout);
                    server.client_identity = Some(tacacsrs_config::TlsClientClientIdentity {
                        credentials_reference: None,
                        certificate: None,
                        raw_private_key: None,
                        tls13_epsk: Some(tacacsrs_config::Tls13Epsk {
                            inline_definition: Some(
                                tacacsrs_config::keystore::SymmetricKeyInlineDefinition {
                                    key_format: None,
                                    cleartext_symmetric_key: Some(psk_key.clone()),
                                    hidden_symmetric_key: None,
                                    encrypted_symmetric_key: None,
                                },
                            ),
                            central_keystore_reference: None,
                            external_identity: psk_identity.clone(),
                            hash: tacacsrs_config::EpskSupportedHash::Sha256,
                            context: None,
                            target_protocol: None,
                            target_kdf: None,
                        }),
                    });
                    ResolvedServer::from_raw(server)
                })
                .collect());
        }

        tls_cert_servers_from_cli(cli, timeout)
    } else {
        Ok(cli
            .server_addresses
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                let mut server = base_server_from_address(addr, i, timeout);
                server.shared_secret.clone_from(&cli.shared_secret);
                ResolvedServer::from_raw(server)
            })
            .collect())
    }
}

/// Build TLS certificate-based server entries from CLI flags.
fn tls_cert_servers_from_cli(cli: &Cli, timeout: u16) -> anyhow::Result<Vec<ResolvedServer>> {
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

    Ok(cli
        .server_addresses
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            let mut server = base_server_from_address(addr, i, timeout);
            if client_cert_pem.is_some() || client_key_pem.is_some() {
                server.client_identity = Some(tacacsrs_config::TlsClientClientIdentity {
                    credentials_reference: None,
                    certificate: Some(tacacsrs_config::ClientIdentityCertificate {
                        inline_definition: Some(
                            tacacsrs_config::keystore::EndEntityCertWithKeyInlineDefinition {
                                public_key_format: None,
                                public_key: None,
                                private_key_format: None,
                                cleartext_private_key: client_key_pem.clone(),
                                hidden_private_key: None,
                                encrypted_private_key: None,
                                cert_data: client_cert_pem.clone(),
                            },
                        ),
                        central_keystore_reference: None,
                    }),
                    raw_private_key: None,
                    tls13_epsk: None,
                });
            } else {
                // TLS without client certs
                server.hello_params = Some(tacacsrs_config::TlsClientHelloParams {
                    tls_versions: None,
                    cipher_suites: None,
                });
            }
            ResolvedServer::from_raw(server)
        })
        .collect())
}

fn base_server_from_address(addr: &str, index: usize, timeout: u16) -> TacacsPlusServer {
    let (host, port) = tacacsrs_networking::helpers::parse_host_port(addr, 49);

    TacacsPlusServer {
        name: format!("server-{index}"),
        server_type: TacacsPlusServerType::all(),
        address: host,
        port,
        shared_secret: None,
        timeout,
        single_connection: false,
        domain_name: None,
        sni_enabled: None,
        client_identity: None,
        server_authentication: None,
        hello_params: None,
        source_ip: None,
        source_interface: None,
        vrf_instance: None,
    }
}

fn servers_from_config(path: &std::path::Path) -> anyhow::Result<Vec<ResolvedServer>> {
    let yang_config = tacacsrs_config::parse_yang_json_file(path, None)
        .with_context(|| format!("Failed to load config from {}", path.display()))?;
    tacacsrs_config::resolve_servers(&yang_config, None)
        .context("Failed to resolve YANG config servers")
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
        servers_from_config(config_path)?
    } else {
        servers_from_cli(&cli)?
    };

    log::info!(
        "Upstream servers: {} configured, probe interval: {}s",
        servers.len(),
        cli.preferred_probe_interval_seconds,
    );
    for server in &servers {
        let security_label = if server.is_tls() {
            "TLS"
        } else {
            "obfuscation"
        };
        log::info!("  {} ({}) -> {}:{}", server.name, security_label, server.address, server.port,);
    }

    let service = TacacsClientService::new(ServiceConfig {
        endpoint,
        servers,
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
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::servers_from_config;

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
    fn servers_from_config_loads_all_servers() {
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

        let servers = servers_from_config(&path).expect("config file should load");
        fs::remove_file(&path).ok();

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "primary");
        assert_eq!(servers[1].name, "secondary");
        assert_eq!(servers[0].shared_secret.as_deref(), Some("secret1"));
    }
}
