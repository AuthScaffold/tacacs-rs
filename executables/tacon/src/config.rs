use std::time::Duration;

use anyhow::Context;
use tacacsrs_config::{ResolvedSecurity, ServerConnectionConfig, TacacsPlusServerType};

use crate::cli::Cli;

/// Builds a `ServerConnectionConfig` from CLI flags for direct-mode connections.
///
/// # Errors
///
/// Returns an error if `--server-addr` is not provided or the address cannot be parsed.
pub fn server_config_from_cli(cli: &Cli) -> anyhow::Result<ServerConnectionConfig> {
    let server_addr = cli
        .server_addr
        .as_deref()
        .context("A TACACS+ server address is required for direct mode")?;

    let (host, port) = match server_addr.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(49)),
        None => (server_addr.to_owned(), 49),
    };

    let security = resolve_security_from_cli(cli)?;

    Ok(ServerConnectionConfig {
        name: "cli".to_owned(),
        server_type: TacacsPlusServerType::all(),
        address: host,
        port,
        security,
        timeout: Duration::from_secs(5),
        single_connection: false,
        domain_name: None,
        sni_enabled: false,
    })
}

fn resolve_security_from_cli(cli: &Cli) -> anyhow::Result<ResolvedSecurity> {
    if cli.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (cli.psk_identity.as_ref(), cli.psk_key.as_ref())
        {
            return Ok(ResolvedSecurity::Psk {
                identity: psk_identity.clone(),
                key: psk_key.clone(),
            });
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

        Ok(ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem: Vec::new(),
            insecure_disable_certificate_verification: cli
                .insecure_disable_certificate_verification,
        })
    } else {
        Ok(ResolvedSecurity::Obfuscation {
            shared_secret: cli.shared_secret.clone(),
        })
    }
}

/// Loads a `ServerConnectionConfig` from a YANG JSON config file, using the first server entry.
///
/// # Errors
///
/// Returns an error if the config file cannot be read, parsed, or contains no servers.
pub fn server_config_from_file(path: &std::path::Path) -> anyhow::Result<ServerConnectionConfig> {
    let yang_config = tacacsrs_config::parse_yang_json_file(path)
        .with_context(|| format!("Failed to load config from {}", path.display()))?;
    let mut configs = tacacsrs_config::to_connection_configs(&yang_config)
        .context("Failed to map YANG config to connection parameters")?;
    if configs.is_empty() {
        anyhow::bail!("Config file contains no server entries");
    }
    Ok(configs.remove(0))
}

/// Resolves a `ServerConnectionConfig` from either `--config` or CLI flags.
///
/// # Errors
///
/// Returns an error if neither source provides valid configuration.
pub fn resolve_server_config(cli: &Cli) -> anyhow::Result<ServerConnectionConfig> {
    if let Some(ref config_path) = cli.config {
        server_config_from_file(config_path)
    } else {
        server_config_from_cli(cli)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::server_config_from_file;
    use tacacsrs_config::ResolvedSecurity;

    fn write_temp_config(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("tacon-config-test-{unique}.json"));
        fs::write(&path, contents).expect("temp config should be written");
        path
    }

    #[test]
    fn server_config_from_file_loads_first_server() {
        let path = write_temp_config(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "primary",
                            "server-type": "accounting",
                            "address": "192.0.2.10",
                            "port": 49,
                            "shared-secret": "secret1"
                        },
                        {
                            "name": "secondary",
                            "server-type": "accounting",
                            "address": "192.0.2.11",
                            "port": 49,
                            "shared-secret": "secret2"
                        }
                    ]
                }
            }"#,
        );

        let config = server_config_from_file(&path).expect("config file should load");
        fs::remove_file(&path).ok();

        assert_eq!(config.name, "primary");
        assert_eq!(config.address, "192.0.2.10");
        assert_eq!(config.port, 49);
        match config.security {
            ResolvedSecurity::Obfuscation { shared_secret } => {
                assert_eq!(shared_secret.as_deref(), Some("secret1"));
            }
            other => panic!("expected obfuscation security, got {other:?}"),
        }
    }
}
