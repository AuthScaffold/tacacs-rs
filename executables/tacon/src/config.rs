use anyhow::Context;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tacacsrs_config::{
    TacacsPlus, TacacsPlusBuilder, TacacsPlusServer, TacacsPlusServerBuilder, TacacsPlusServerExt,
    TacacsPlusServerType, ValidationOptions, crypto_types::PrivateKeyFormat,
};

use crate::cli::{Cli, Command};
#[cfg(feature = "psk")]
use crate::cli::PskKeyExchange;

fn data_contains_pem_header(data: &[u8]) -> bool {
    const PEM_HEADER: &[u8] = b"-----BEGIN";

    data.windows(PEM_HEADER.len())
        .any(|window| window == PEM_HEADER)
}

fn normalize_cli_certificate_data(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.is_empty() {
        anyhow::bail!("client certificate data is empty");
    }

    if !data_contains_pem_header(data) {
        return Ok(data.to_vec());
    }

    let certificates = CertificateDer::pem_slice_iter(data)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse PEM client certificate")?;

    if certificates.len() != 1 {
        anyhow::bail!("client certificate file must contain exactly one PEM certificate");
    }

    Ok(certificates[0].as_ref().to_vec())
}

fn normalize_cli_private_key_data(data: &[u8]) -> anyhow::Result<(Vec<u8>, PrivateKeyFormat)> {
    if data.is_empty() {
        anyhow::bail!("client private key data is empty");
    }

    let private_key = if data_contains_pem_header(data) {
        PrivateKeyDer::from_pem_slice(data).context("failed to parse PEM client private key")?
    } else {
        PrivateKeyDer::try_from(data).map_err(|_| {
            anyhow::anyhow!(
                "unsupported DER client private key format; expected PKCS#1, SEC1, or PKCS#8"
            )
        })?
    };

    let private_key_format = match &private_key {
        PrivateKeyDer::Pkcs1(_) => PrivateKeyFormat::RsaPrivateKeyFormat,
        PrivateKeyDer::Sec1(_) => PrivateKeyFormat::EcPrivateKeyFormat,
        PrivateKeyDer::Pkcs8(_) => PrivateKeyFormat::OneAsymmetricKeyFormat,
        _ => anyhow::bail!("unsupported client private key format"),
    };

    Ok((private_key.secret_der().to_vec(), private_key_format))
}

fn parse_host_port(addr: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, after_bracket)) = rest.split_once(']') {
            let port = after_bracket
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (host.to_owned(), port);
        }
    }

    if addr.matches(':').count() == 1 {
        if let Some((host, port_str)) = addr.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return (host.to_owned(), port);
            }
        }
    }

    (addr.to_owned(), default_port)
}

/// Builds a single-server [`TacacsPlus`] root from CLI flags for direct-mode connections.
///
/// # Errors
///
/// Returns an error if `--server-addr` is not provided or the address cannot be parsed.
pub fn tacacs_plus_from_cli(cli: &Cli) -> anyhow::Result<TacacsPlus> {
    let options = validation_options_from_cli(cli);

    let server_addr = cli
        .server_addr
        .as_deref()
        .context("A TACACS+ server address is required for direct mode")?;

    let (host, port) = parse_host_port(server_addr, 49);

    let mut server = populate_security_from_cli(
        cli,
        TacacsPlusServerBuilder::new("cli", TacacsPlusServerType::all(), host, port)
            .with_timeout(5),
        &options,
    )?;
    server.single_connection = true;

    TacacsPlusBuilder::new()
        .with_server(server)
        .build_with_options(&options)
}

fn validation_options_from_cli(cli: &Cli) -> ValidationOptions {
    // cli::ValidationRelaxation is a separate enum that mirrors
    // tacacsrs_config::ValidationRelaxation.  The duplication is intentional:
    // build.rs includes cli.rs via `include!` to auto-generate the man page, so
    // cli.rs may only depend on crates listed in [build-dependencies]. This
    // function is the single mapping point, so adding a new relaxation requires
    // one change here and one in cli.rs.
    use crate::cli::ValidationRelaxation as CliRelaxation;
    use tacacsrs_config::ValidationRelaxation;

    cli.validation_relaxation
        .iter()
        .fold(ValidationOptions::new(), |opts, r| {
            let relaxation = match r {
                CliRelaxation::AllowTlsWithSharedSecret => {
                    ValidationRelaxation::AllowTlsWithSharedSecret
                }
                CliRelaxation::AllowPlainTcpWithoutSharedSecret => {
                    ValidationRelaxation::AllowPlainTcpWithoutSharedSecret
                }
            };
            opts.with_relaxation(relaxation)
        })
}

fn populate_security_from_cli(
    cli: &Cli,
    builder: TacacsPlusServerBuilder,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlusServer> {
    use tacacsrs_config::ValidationRelaxation;

    if cli.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (cli.psk_identity.as_ref(), cli.psk_key.as_ref())
        {
            let tls_builder = apply_psk_key_exchange(
                cli,
                builder,
                psk_identity.clone(),
                psk_key.as_bytes().to_vec(),
            )?;

            if options.allows(&ValidationRelaxation::AllowTlsWithSharedSecret) {
                if let Some(ref secret) = cli.shared_secret {
                    return Ok(tls_builder
                        .with_shared_secret_alongside_tls(secret.clone())
                        .build());
                }
            }
            return Ok(tls_builder.build());
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

        let tls_builder = if client_cert_der.is_some() || client_key_der.is_some() {
            builder.with_tls_client_certificate_with_key_format(
                client_cert_der,
                client_key_der,
                client_key_format,
            )
        } else {
            builder.with_tls_server_authentication()
        };

        if options.allows(&ValidationRelaxation::AllowTlsWithSharedSecret) {
            if let Some(ref secret) = cli.shared_secret {
                return Ok(tls_builder
                    .with_shared_secret_alongside_tls(secret.clone())
                    .build());
            }
        }

        Ok(tls_builder.build())
    } else {
        Ok(match cli.shared_secret.clone() {
            Some(shared_secret) => builder.with_shared_secret(shared_secret).build(),
            None => builder.build(),
        })
    }
}

#[cfg(feature = "psk")]
fn apply_psk_key_exchange(
    cli: &Cli,
    builder: TacacsPlusServerBuilder,
    psk_identity: String,
    psk_key: Vec<u8>,
) -> anyhow::Result<TacacsPlusServerBuilder> {
    if matches!(cli.psk_key_exchange, Some(PskKeyExchange::PskOnly))
        && !cli.psk_key_exchange_groups.is_empty()
    {
        anyhow::bail!(
            "--psk-key-exchange psk-only cannot be combined with --psk-key-exchange-groups; remove the groups or use --psk-key-exchange psk-dhe"
        );
    }

    Ok(match cli.psk_key_exchange {
        Some(PskKeyExchange::PskOnly) => builder.with_tls13_epsk_psk_only(psk_identity, psk_key),
        Some(PskKeyExchange::PskDhe) | None if !cli.psk_key_exchange_groups.is_empty() => builder
            .with_tls13_epsk_with_psk_dhe_groups(
                psk_identity,
                psk_key,
                cli.psk_key_exchange_groups.clone(),
            ),
        Some(PskKeyExchange::PskDhe) | None => builder.with_tls13_epsk(psk_identity, psk_key),
    })
}

/// Loads a [`TacacsPlus`] root from a YANG JSON string with the supplied validation options.
///
/// # Errors
///
/// Returns an error if the config cannot be parsed.
pub fn tacacs_plus_from_str(
    contents: &str,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    tacacsrs_config::parse_yang_json_with_options(contents, options)
        .context("Failed to load config from provided YANG JSON")
}

/// Loads a [`TacacsPlus`] root from a YANG JSON config file with the supplied validation options.
///
/// # Errors
///
/// Returns an error if the config file cannot be read or parsed.
pub fn tacacs_plus_from_file(
    path: &std::path::Path,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config from {}", path.display()))?;

    tacacs_plus_from_str(&contents, options)
        .with_context(|| format!("Failed to load config from {}", path.display()))
}

/// Resolves a [`TacacsPlus`] root configuration from either `--config` or CLI flags.
///
/// # Errors
///
/// Returns an error if neither source provides valid configuration.
pub fn resolve_tacacs_plus_config(cli: &Cli) -> anyhow::Result<TacacsPlus> {
    let options = validation_options_from_cli(cli);
    if let Some(ref config_path) = cli.config {
        tacacs_plus_from_file(config_path, &options)
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
    #[cfg(feature = "psk")]
    use tacacsrs_config::PskDheKeSupportedGroup;
    use tacacsrs_config::{TacacsPlusServerType, ValidationOptions, crypto_types::PrivateKeyFormat};

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
            &ValidationOptions::default(),
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
            &ValidationOptions::default(),
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
            &ValidationOptions::default(),
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
    fn tacacs_plus_from_cli_enables_single_connection_negotiation() {
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

        let root = tacacs_plus_from_cli(&cli).expect("CLI server config should load");

        assert!(root.server[0].single_connection);
    }

    #[test]
    fn tacacs_plus_from_cli_with_relaxation_allows_plain_tcp_without_shared_secret() {
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--validation-relaxation",
            "allow-plain-tcp-without-shared-secret",
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);

        let root = tacacs_plus_from_cli(&cli)
            .expect("plain TCP without shared-secret should load with relaxation");
        assert!(root.server[0].shared_secret.is_none());
        assert!(root.server[0].client_identity.is_none());
        assert!(root.server[0].server_authentication.is_none());
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

    #[test]
    fn tacacs_plus_from_cli_with_relaxation_allows_tls_and_shared_secret() {
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--use-tls",
            "--shared-secret",
            "migration-secret",
            "--validation-relaxation",
            "allow-tls-with-shared-secret",
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);

        let root = tacacs_plus_from_cli(&cli).expect(
            "AllowTlsWithSharedSecret relaxation should allow TLS + shared-secret from CLI",
        );

        assert!(root.server[0].server_authentication.is_some(), "TLS should be set");
        assert_eq!(
            root.server[0].shared_secret.as_deref(),
            Some("migration-secret"),
            "shared secret should be set alongside TLS",
        );
    }

    #[test]
    fn tacacs_plus_from_cli_without_relaxation_does_not_include_shared_secret_for_tls() {
        // Without the relaxation, --use-tls ignores --shared-secret (TLS wins).
        // This verifies that the default strict path continues to build a TLS-only server.
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--use-tls",
            "--shared-secret",
            "ignored-secret",
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);

        let root = tacacs_plus_from_cli(&cli)
            .expect("TLS-only server should build successfully without relaxation");

        assert!(root.server[0].server_authentication.is_some(), "TLS should be set");
        assert!(
            root.server[0].shared_secret.is_none(),
            "shared secret should not be set without relaxation",
        );
    }

    #[cfg(feature = "psk")]
    fn tls13_epsk_groups(cli: &Cli) -> Vec<PskDheKeSupportedGroup> {
        let mut root = tacacs_plus_from_cli(cli).expect("PSK config should build");
        root.server
            .remove(0)
            .client_identity
            .expect("client identity")
            .tls13_epsk
            .expect("tls13 epsk")
            .psk_dhe_ke_groups
    }

    #[cfg(feature = "psk")]
    #[test]
    fn tacacs_plus_from_cli_defaults_psk_to_dhe_groups() {
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            "secret",
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);

        let groups = tls13_epsk_groups(&cli);

        assert!(matches!(groups.first(), Some(PskDheKeSupportedGroup::Secp384r1)));
        assert!(matches!(groups.get(1), Some(PskDheKeSupportedGroup::Secp256r1)));
    }

    #[cfg(feature = "psk")]
    #[test]
    fn tacacs_plus_from_cli_allows_psk_only_mode() {
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            "secret",
            "--psk-key-exchange",
            "psk-only",
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);

        assert!(tls13_epsk_groups(&cli).is_empty());
    }

    #[cfg(feature = "psk")]
    #[test]
    fn tacacs_plus_from_cli_uses_custom_psk_dhe_groups() {
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            "secret",
            "--psk-key-exchange-groups",
            "secp256r1,x25519",
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);

        let groups = tls13_epsk_groups(&cli);

        assert!(matches!(groups.first(), Some(PskDheKeSupportedGroup::Secp256r1)));
        assert!(matches!(groups.get(1), Some(PskDheKeSupportedGroup::X25519)));
    }

    #[cfg(feature = "psk")]
    #[test]
    fn tacacs_plus_from_cli_rejects_psk_only_with_groups() {
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:49",
            "--use-tls",
            "--psk-identity",
            "client",
            "--psk-key",
            "secret",
            "--psk-key-exchange",
            "psk-only",
            "--psk-key-exchange-groups",
            "secp384r1",
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);

        let error = tacacs_plus_from_cli(&cli).expect_err("PSK-only plus groups should fail");
        assert!(error.to_string().contains("--psk-key-exchange psk-only"));
        assert!(error.to_string().contains("--psk-key-exchange-groups"));
    }
}
