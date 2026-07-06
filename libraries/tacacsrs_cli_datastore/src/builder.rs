use std::path::Path;

use anyhow::Context;
use tacacsrs_config::{
    TacacsPlus, TacacsPlusBuilder, TacacsPlusServer, TacacsPlusServerBuilder, ValidationOptions,
};

use crate::address::parse_host_port;
use crate::files::{load_client_certificate, load_client_private_key};
use crate::model::{
    CertKeyIdentity, CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityMode,
    CliServerInput, PskKeyExchangeMode, PskKeyMaterial,
};

/// Loads a [`TacacsPlus`] root from a YANG JSON string with the supplied validation options.
///
/// # Errors
///
/// Returns an error if the config cannot be parsed or validated.
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
/// Returns an error if the config file cannot be read, parsed, or validated.
pub fn tacacs_plus_from_file(
    path: &Path,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config from {}", path.display()))?;

    tacacs_plus_from_str(&contents, options)
        .with_context(|| format!("Failed to load config from {}", path.display()))
}

/// Build a validated [`TacacsPlus`] root from parsed CLI/file inputs.
///
/// # Errors
///
/// Returns an error if referenced files cannot be read or if validation fails.
pub fn tacacs_plus_from_cli_input(input: &CliDatastoreInput) -> anyhow::Result<TacacsPlus> {
    match &input.source {
        CliConfigSource::YangFile { path } => {
            tacacs_plus_from_file(path, &input.validation_options)
        }
        CliConfigSource::Inline { servers, security } => {
            inline_tacacs_plus_from_cli_input(servers, security, &input.validation_options)
        }
    }
}

fn inline_tacacs_plus_from_cli_input(
    servers: &[CliServerInput],
    security: &CliSecurity,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    servers
        .iter()
        .map(|server| server_from_cli_input(server, security, options))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .fold(TacacsPlusBuilder::new(), TacacsPlusBuilder::with_server)
        .build_with_options(options)
}

fn server_from_cli_input(
    input: &CliServerInput,
    security: &CliSecurity,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlusServer> {
    let (host, port) = parse_host_port(&input.address, 49);
    let builder = TacacsPlusServerBuilder::new(&input.name, input.server_type, host, port)
        .with_timeout(input.timeout_seconds)
        .with_single_connection(input.single_connection);

    let shared_secret = security.shared_secret.as_ref();
    let mut server = match &security.mode {
        CliSecurityMode::PlainTcp => match shared_secret {
            Some(shared_secret) => builder.with_shared_secret(shared_secret.clone()).build(),
            None => builder.build(),
        },
        CliSecurityMode::TlsServerAuthentication => tls_builder_with_optional_shared_secret(
            builder.with_tls_server_authentication(),
            shared_secret,
            options,
        )
        .build(),
        CliSecurityMode::TlsClientCertificate { identity } => {
            let tls_builder = tls_client_certificate_builder(builder, identity)?;
            tls_builder_with_optional_shared_secret(tls_builder, shared_secret, options).build()
        }
        CliSecurityMode::TlsPsk {
            identity,
            key,
            exchange,
            groups,
        } => {
            let tls_builder =
                psk_builder(builder, identity.clone(), key.clone(), *exchange, groups)?;
            tls_builder_with_optional_shared_secret(tls_builder, shared_secret, options).build()
        }
    };

    if let Some(tls_server_name) = &input.tls_server_name {
        server.domain_name = Some(tls_server_name.domain_name.clone());
        server.sni_enabled = Some(tls_server_name.sni_enabled);
    }

    Ok(server)
}

fn tls_builder_with_optional_shared_secret(
    builder: TacacsPlusServerBuilder,
    shared_secret: Option<&String>,
    options: &ValidationOptions,
) -> TacacsPlusServerBuilder {
    use tacacsrs_config::ValidationRelaxation;

    if options.allows(&ValidationRelaxation::AllowTlsWithSharedSecret) {
        if let Some(shared_secret) = shared_secret {
            return builder.with_shared_secret_alongside_tls(shared_secret.clone());
        }
    }
    builder
}

fn tls_client_certificate_builder(
    builder: TacacsPlusServerBuilder,
    identity: &CertKeyIdentity,
) -> anyhow::Result<TacacsPlusServerBuilder> {
    let client_cert_der = load_client_certificate(&identity.certificate_path)?;
    let (client_key_der, client_key_format) = load_client_private_key(&identity.private_key_path)?;

    Ok(builder.with_tls_client_certificate_with_key_format(
        Some(client_cert_der),
        Some(client_key_der),
        Some(client_key_format),
    ))
}

fn psk_builder(
    builder: TacacsPlusServerBuilder,
    identity: String,
    key: PskKeyMaterial,
    exchange: PskKeyExchangeMode,
    groups: &[tacacsrs_config::PskDheKeSupportedGroup],
) -> anyhow::Result<TacacsPlusServerBuilder> {
    if exchange == PskKeyExchangeMode::PskOnly && !groups.is_empty() {
        anyhow::bail!(
            "--psk-key-exchange psk-only cannot be combined with --psk-key-exchange-groups; remove the groups or use --psk-key-exchange psk-dhe"
        );
    }

    let key = key.into_bytes()?;
    Ok(match exchange {
        PskKeyExchangeMode::PskOnly => builder.with_tls13_epsk_psk_only(identity, key),
        PskKeyExchangeMode::PskDhe if !groups.is_empty() => {
            builder.with_tls13_epsk_with_psk_dhe_groups(identity, key, groups.to_vec())
        }
        PskKeyExchangeMode::PskDhe => builder.with_tls13_epsk(identity, key),
    })
}
