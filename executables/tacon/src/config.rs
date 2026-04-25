use anyhow::Context;
use tacacsrs_config::{
    TacacsPlus, TacacsPlusBuilder, TacacsPlusServer, TacacsPlusServerBuilder, TacacsPlusServerType,
};

use crate::cli::Cli;

/// Builds a single-server [`TacacsPlus`] root from CLI flags for direct-mode connections.
///
/// # Errors
///
/// Returns an error if `--server-addr` is not provided or the address cannot be parsed.
pub fn tacacs_plus_from_cli(cli: &Cli) -> anyhow::Result<TacacsPlus> {
    let server_addr = cli
        .server_addr
        .as_deref()
        .context("A TACACS+ server address is required for direct mode")?;

    let (host, port) = tacacsrs_networking::helpers::parse_host_port(server_addr, 49);

    let server = populate_security_from_cli(
        cli,
        TacacsPlusServerBuilder::new("cli", TacacsPlusServerType::all(), host, port)
            .with_timeout(5),
    )?;

    Ok(TacacsPlusBuilder::new().with_server(server).build())
}

fn populate_security_from_cli(
    cli: &Cli,
    builder: TacacsPlusServerBuilder,
) -> anyhow::Result<TacacsPlusServer> {
    if cli.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (cli.psk_identity.as_ref(), cli.psk_key.as_ref())
        {
            return Ok(builder
                .with_tls13_epsk(psk_identity.clone(), psk_key.as_bytes().to_vec())
                .build());
        }

        let client_cert_der = cli
            .client_certificate
            .as_ref()
            .map(|path| {
                std::fs::read(path)
                    .with_context(|| format!("Failed to read client certificate: {path}"))
            })
            .transpose()?;
        let client_key_der = cli
            .client_key
            .as_ref()
            .map(|path| {
                std::fs::read(path).with_context(|| format!("Failed to read client key: {path}"))
            })
            .transpose()?;

        if client_cert_der.is_some() || client_key_der.is_some() {
            Ok(builder
                .with_tls_client_certificate(client_cert_der, client_key_der)
                .build())
        } else {
            Ok(builder.with_tls_server_authentication().build())
        }
    } else {
        Ok(match cli.shared_secret.clone() {
            Some(shared_secret) => builder.with_shared_secret(shared_secret).build(),
            None => builder.build(),
        })
    }
}

/// Loads a [`TacacsPlus`] root from a YANG JSON config file.
///
/// # Errors
///
/// Returns an error if the config file cannot be read or parsed.
pub fn tacacs_plus_from_file(path: &std::path::Path) -> anyhow::Result<TacacsPlus> {
    tacacsrs_config::parse_yang_json_file(path)
        .with_context(|| format!("Failed to load config from {}", path.display()))
}

/// Resolves a [`TacacsPlus`] root configuration from either `--config` or CLI flags.
///
/// # Errors
///
/// Returns an error if neither source provides valid configuration.
pub fn resolve_tacacs_plus_config(cli: &Cli) -> anyhow::Result<TacacsPlus> {
    if let Some(ref config_path) = cli.config {
        tacacs_plus_from_file(config_path)
    } else {
        tacacs_plus_from_cli(cli)
    }
}

/// Resolves the first upstream server from the CLI's effective [`TacacsPlus`] config.
///
/// This is the entry point used by direct-mode commands, which operate on a
/// single server. Credential references in the parsed config are resolved via
/// [`tacacsrs_config::enumerate_servers`].
///
/// # Errors
///
/// Returns an error if the resolved configuration contains no servers, or if
/// credential-reference resolution fails.
pub fn resolve_first_server(cli: &Cli) -> anyhow::Result<TacacsPlusServer> {
    let root = resolve_tacacs_plus_config(cli)?;
    let mut servers = tacacsrs_config::enumerate_servers(&root)
        .context("Failed to enumerate TACACS+ servers from configuration")?;
    if servers.is_empty() {
        anyhow::bail!("No TACACS+ servers configured");
    }
    Ok(servers.remove(0))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::tacacs_plus_from_file;

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
    fn tacacs_plus_from_file_loads_root() {
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

        let root = tacacs_plus_from_file(&path).expect("config file should load");
        fs::remove_file(&path).ok();

        assert_eq!(root.server.len(), 2);
        assert_eq!(root.server[0].name, "primary");
        assert_eq!(root.server[0].address, "192.0.2.10");
        assert_eq!(root.server[0].port, 49);
        assert_eq!(root.server[0].shared_secret.as_deref(), Some("secret1"));
    }
}
