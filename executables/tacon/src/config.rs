use anyhow::Context;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerType};
use tacacsrs_credentials::{ResolvedServer, resolve_server, resolve_servers};

use crate::cli::Cli;

/// Builds a `ResolvedServer` from CLI flags for direct-mode connections.
///
/// # Errors
///
/// Returns an error if `--server-addr` is not provided or the address cannot be parsed.
pub fn server_config_from_cli(cli: &Cli) -> anyhow::Result<ResolvedServer> {
    let server_addr = cli
        .server_addr
        .as_deref()
        .context("A TACACS+ server address is required for direct mode")?;

    let (host, port) = tacacsrs_networking::helpers::parse_host_port(server_addr, 49);

    let mut server = TacacsPlusServer {
        name: "cli".to_owned(),
        server_type: TacacsPlusServerType::all(),
        address: host,
        port,
        shared_secret: None,
        timeout: 5,
        single_connection: false,
        domain_name: None,
        sni_enabled: None,
        client_identity: None,
        server_authentication: None,
        hello_params: None,
        source_ip: None,
        source_interface: None,
        vrf_instance: None,
    };

    populate_security_from_cli(cli, &mut server)?;

    resolve_server(server, None)
}

fn populate_security_from_cli(cli: &Cli, server: &mut TacacsPlusServer) -> anyhow::Result<()> {
    if cli.use_tls {
        #[cfg(feature = "psk")]
        if let (Some(psk_identity), Some(psk_key)) =
            (cli.psk_identity.as_ref(), cli.psk_key.as_ref())
        {
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
            return Ok(());
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

        if client_cert_pem.is_some() || client_key_pem.is_some() {
            server.client_identity = Some(tacacsrs_config::TlsClientClientIdentity {
                credentials_reference: None,
                certificate: Some(tacacsrs_config::ClientIdentityCertificate {
                    inline_definition: Some(
                        tacacsrs_config::keystore::EndEntityCertWithKeyInlineDefinition {
                            public_key_format: None,
                            public_key: None,
                            private_key_format: None,
                            cleartext_private_key: client_key_pem,
                            hidden_private_key: None,
                            encrypted_private_key: None,
                            cert_data: client_cert_pem,
                        },
                    ),
                    central_keystore_reference: None,
                }),
                raw_private_key: None,
                tls13_epsk: None,
            });
        } else {
            // TLS without client certs — hello-params-only or server-auth-only
            server.hello_params = Some(tacacsrs_config::TlsClientHelloParams {
                tls_versions: None,
                cipher_suites: None,
            });
        }
    } else {
        server.shared_secret.clone_from(&cli.shared_secret);
    }

    Ok(())
}

/// Loads a `ResolvedServer` from a YANG JSON config file, using the first server entry.
///
/// # Errors
///
/// Returns an error if the config file cannot be read, parsed, or contains no servers.
pub fn server_config_from_file(path: &std::path::Path) -> anyhow::Result<ResolvedServer> {
    let yang_config = tacacsrs_config::parse_yang_json_file(path)
        .with_context(|| format!("Failed to load config from {}", path.display()))?;
    let enumerated_servers = tacacsrs_config::enumerate_servers(&yang_config)
        .context("Failed to enumerate YANG config servers")?;
    let mut servers = resolve_servers(enumerated_servers, None)
        .context("Failed to resolve YANG config servers")?;
    if servers.is_empty() {
        anyhow::bail!("Config file contains no server entries");
    }
    Ok(servers.remove(0))
}

/// Resolves a `ResolvedServer` from either `--config` or CLI flags.
///
/// # Errors
///
/// Returns an error if neither source provides valid configuration.
pub fn resolve_server_config(cli: &Cli) -> anyhow::Result<ResolvedServer> {
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

        let server = server_config_from_file(&path).expect("config file should load");
        fs::remove_file(&path).ok();

        assert_eq!(server.name, "primary");
        assert_eq!(server.address, "192.0.2.10");
        assert_eq!(server.port, 49);
        assert_eq!(server.shared_secret.as_deref(), Some("secret1"));
    }
}
