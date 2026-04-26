use anyhow::Context;
use tacacsrs_config::{
    TacacsPlus, TacacsPlusBuilder, TacacsPlusServer, TacacsPlusServerBuilder, TacacsPlusServerExt,
    TacacsPlusServerType,
};
use tacacsrs_networking::helpers::{normalize_cli_certificate_data, normalize_cli_private_key_data};

use crate::cli::{Cli, Command};

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

    TacacsPlusBuilder::new().with_server(server).build()
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

        if client_cert_der.is_some() || client_key_der.is_some() {
            Ok(builder
                .with_tls_client_certificate_with_key_format(
                    client_cert_der,
                    client_key_der,
                    client_key_format,
                )
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

/// Loads a [`TacacsPlus`] root from a YANG JSON string.
///
/// # Errors
///
/// Returns an error if the config cannot be parsed.
pub fn tacacs_plus_from_str(contents: &str) -> anyhow::Result<TacacsPlus> {
    tacacsrs_config::parse_yang_json(contents)
        .context("Failed to load config from provided YANG JSON")
}

/// Loads a [`TacacsPlus`] root from a YANG JSON config file.
///
/// # Errors
///
/// Returns an error if the config file cannot be read or parsed.
pub fn tacacs_plus_from_file(path: &std::path::Path) -> anyhow::Result<TacacsPlus> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config from {}", path.display()))?;

    tacacs_plus_from_str(&contents)
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

/// Resolves the first upstream server with the requested service type from the
/// CLI's effective [`TacacsPlus`] config.
///
/// This is the entry point used by direct-mode commands, which operate on a
/// single server. Credential references in the parsed config are resolved via
/// [`tacacsrs_config::enumerate_servers`].
///
/// # Errors
///
/// Returns an error if the resolved configuration contains no matching server,
/// or if credential-reference resolution fails.
pub fn resolve_server_for_type(
    cli: &Cli,
    required_type: TacacsPlusServerType,
) -> anyhow::Result<TacacsPlusServer> {
    let root = resolve_tacacs_plus_config(cli)?;
    select_first_server_for_type(&root, required_type)
}

/// Resolves the upstream server required by a direct-mode command.
///
/// # Errors
///
/// Returns an error if the command has no direct server type or if no configured
/// server supports the command's required service.
pub fn resolve_server_for_command(
    cli: &Cli,
    command: &Command,
) -> anyhow::Result<TacacsPlusServer> {
    let required_type = server_type_for_command(command)
        .context("Batch commands must resolve their server type from the batch file")?;
    resolve_server_for_type(cli, required_type)
}

fn select_first_server_for_type(
    root: &TacacsPlus,
    required_type: TacacsPlusServerType,
) -> anyhow::Result<TacacsPlusServer> {
    let servers = tacacsrs_config::enumerate_servers(root)
        .context("Failed to enumerate TACACS+ servers from configuration")?;

    if required_type.is_empty() {
        anyhow::bail!("A non-empty TACACS+ server type is required");
    }

    servers
        .into_iter()
        .find(|server| server.supports_server_type(required_type))
        .ok_or_else(|| {
            anyhow::anyhow!("No TACACS+ server configured for {}", server_type_label(required_type))
        })
}

const fn server_type_for_command(command: &Command) -> Option<TacacsPlusServerType> {
    match command {
        Command::Accounting { .. } => Some(TacacsPlusServerType::ACCOUNTING),
        Command::Authentication { .. } => Some(TacacsPlusServerType::AUTHENTICATION),
        Command::Authorization { .. } => Some(TacacsPlusServerType::AUTHORIZATION),
        Command::Batch { .. } => None,
    }
}

fn server_type_label(server_type: TacacsPlusServerType) -> String {
    [
        (TacacsPlusServerType::AUTHENTICATION, "authentication"),
        (TacacsPlusServerType::AUTHORIZATION, "authorization"),
        (TacacsPlusServerType::ACCOUNTING, "accounting"),
    ]
    .into_iter()
    .filter_map(|(flag, label)| server_type.contains(flag).then_some(label))
    .collect::<Vec<_>>()
    .join(" ")
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;

    use super::{select_first_server_for_type, tacacs_plus_from_cli, tacacs_plus_from_str};
    use crate::cli::Cli;
    use tacacsrs_config::{TacacsPlusServerType, crypto_types::PrivateKeyFormat};

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

    #[test]
    fn tacacs_plus_from_str_loads_root() {
        let root = tacacs_plus_from_str(
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
        )
        .expect("config string should load");

        assert_eq!(root.server.len(), 2);
        assert_eq!(root.server[0].name, "primary");
        assert_eq!(root.server[0].address, "192.0.2.10");
        assert_eq!(root.server[0].port, 49);
        assert_eq!(root.server[0].shared_secret.as_deref(), Some("secret1"));
    }

    #[test]
    fn select_first_server_for_type_skips_servers_without_requested_type() {
        let root = tacacs_plus_from_str(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "auth-only",
                            "server-type": "authentication",
                            "address": "192.0.2.10",
                            "port": 49,
                            "shared-secret": "secret1"
                        },
                        {
                            "name": "acct",
                            "server-type": "accounting",
                            "address": "192.0.2.11",
                            "port": 49,
                            "shared-secret": "secret2"
                        }
                    ]
                }
            }"#,
        )
        .expect("config string should load");

        let server = select_first_server_for_type(&root, TacacsPlusServerType::ACCOUNTING)
            .expect("accounting server should be selected");
        assert_eq!(server.name, "acct");
    }

    #[test]
    fn select_first_server_for_type_errors_when_no_server_supports_type() {
        let root = tacacs_plus_from_str(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "auth-only",
                            "server-type": "authentication",
                            "address": "192.0.2.10",
                            "port": 49,
                            "shared-secret": "secret1"
                        }
                    ]
                }
            }"#,
        )
        .expect("config string should load");

        let error = select_first_server_for_type(&root, TacacsPlusServerType::ACCOUNTING)
            .expect_err("accounting server should be required");
        assert!(error
            .to_string()
            .contains("No TACACS+ server configured for accounting"));
    }

    #[test]
    fn tacacs_plus_from_cli_accepts_plain_text_shared_secret() {
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "secret123",
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);

        let root = tacacs_plus_from_cli(&cli).expect("plain-text shared secret should load");
        assert_eq!(root.server[0].shared_secret.as_deref(), Some("secret123"));
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
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--use-tls",
            "--client-certificate",
            cert_path.to_str().expect("path should be UTF-8"),
            "--client-key",
            key_path.to_str().expect("path should be UTF-8"),
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
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
