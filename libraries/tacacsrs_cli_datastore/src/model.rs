use std::path::PathBuf;
use std::time::Duration;

#[cfg(feature = "psk")]
use anyhow::Context;
#[cfg(feature = "psk")]
use base64::Engine as _;
#[cfg(feature = "psk")]
use tacacsrs_config::PskDheKeSupportedGroup;
use tacacsrs_config::{TacacsPlusServerType, ValidationOptions};

/// Parsed CLI inputs that can produce TACACS+ configuration.
///
/// Construct with [`CliDatastoreInput::new`] and the `with_*` methods; the
/// fields are crate-private so the construction path stays the single source of
/// defaults.
#[derive(Debug, Clone)]
pub struct CliDatastoreInput {
    pub(crate) source: CliConfigSource,
    pub(crate) validation_options: ValidationOptions,
    pub(crate) label: &'static str,
    pub(crate) debounce: Duration,
}

impl CliDatastoreInput {
    /// Create a new input model with strict validation and a conservative debounce.
    #[must_use]
    pub fn new(source: CliConfigSource, label: &'static str) -> Self {
        Self {
            source,
            validation_options: ValidationOptions::default(),
            label,
            debounce: Duration::from_millis(200),
        }
    }

    #[must_use]
    pub fn with_validation_options(mut self, validation_options: ValidationOptions) -> Self {
        self.validation_options = validation_options;
        self
    }

    #[must_use]
    pub fn with_debounce(mut self, debounce: Duration) -> Self {
        self.debounce = debounce;
        self
    }

    #[must_use]
    pub fn watched_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        match &self.source {
            CliConfigSource::YangFile { path } => paths.push(path.clone()),
            CliConfigSource::Inline { security, .. } => security.extend_watched_paths(&mut paths),
        }
        paths
    }
}

/// Source of the TACACS+ root configuration.
#[derive(Debug, Clone)]
pub enum CliConfigSource {
    /// A YANG JSON configuration file loaded (and watched) from disk.
    YangFile { path: PathBuf },
    /// Inline servers built from CLI flags. `security` applies uniformly to
    /// every server in `servers`.
    Inline {
        servers: Vec<CliServerInput>,
        security: CliSecurity,
    },
}

/// Parsed CLI inputs for one TACACS+ server.
#[derive(Debug, Clone)]
pub struct CliServerInput {
    pub name: String,
    pub address: String,
    pub server_type: TacacsPlusServerType,
    pub timeout_seconds: u16,
    pub single_connection: bool,
    pub tls_server_name: Option<TlsServerName>,
}

impl CliServerInput {
    #[must_use]
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            server_type: TacacsPlusServerType::all(),
            timeout_seconds: 5,
            single_connection: true,
            tls_server_name: None,
        }
    }

    #[must_use]
    pub fn with_timeout_seconds(mut self, timeout_seconds: u16) -> Self {
        self.timeout_seconds = timeout_seconds;
        self
    }

    #[must_use]
    pub fn with_single_connection(mut self, single_connection: bool) -> Self {
        self.single_connection = single_connection;
        self
    }

    #[must_use]
    pub fn with_tls_server_name(mut self, tls_server_name: impl Into<String>) -> Self {
        self.tls_server_name = Some(TlsServerName {
            domain_name: tls_server_name.into(),
            sni_enabled: true,
        });
        self
    }
}

#[derive(Debug, Clone)]
pub struct TlsServerName {
    pub domain_name: String,
    pub sni_enabled: bool,
}

/// Security configuration derived from parsed CLI fields.
///
/// The security *mode* is orthogonal to `shared_secret`: a shared secret may
/// accompany a TLS mode only as a migration aid, and is honored during
/// construction solely when the active [`ValidationOptions`] allow it.
#[derive(Debug, Clone)]
pub struct CliSecurity {
    pub mode: CliSecurityMode,
    pub shared_secret: Option<String>,
}

impl CliSecurity {
    /// Derive the security configuration from neutral CLI inputs.
    ///
    /// This is the single decision point that maps `--use-tls`, PSK, client
    /// certificate, and shared-secret flags onto a [`CliSecurityMode`]. Both
    /// `tacacsrs-agentd` and `tacon` funnel their parsed flags through here so
    /// the mode-selection logic cannot drift between executables.
    #[must_use]
    pub fn from_cli_inputs(inputs: CliSecurityInputs) -> Self {
        let shared_secret = inputs.shared_secret;

        if !inputs.use_tls {
            return Self {
                mode: CliSecurityMode::PlainTcp,
                shared_secret,
            };
        }

        #[cfg(feature = "psk")]
        if let Some(psk) = inputs.psk {
            return Self {
                mode: CliSecurityMode::TlsPsk {
                    identity: psk.identity,
                    key: psk.key,
                    exchange: psk.exchange,
                    groups: psk.groups,
                },
                shared_secret,
            };
        }

        let mode = match (inputs.client_certificate, inputs.client_key) {
            (Some(certificate_path), Some(private_key_path)) => {
                CliSecurityMode::TlsClientCertificate {
                    identity: CertKeyIdentity::new(certificate_path, private_key_path),
                }
            }
            _ => CliSecurityMode::TlsServerAuthentication,
        };

        Self {
            mode,
            shared_secret,
        }
    }

    pub(crate) fn extend_watched_paths(&self, paths: &mut Vec<PathBuf>) {
        if let CliSecurityMode::TlsClientCertificate { identity } = &self.mode {
            identity.extend_watched_paths(paths);
        }
    }
}

/// Security mode selected by the CLI, independent of any shared secret.
#[derive(Debug, Clone)]
pub enum CliSecurityMode {
    /// Plain TCP with optional TACACS+ obfuscation via a shared secret.
    PlainTcp,
    /// TLS with server authentication only (no client identity).
    TlsServerAuthentication,
    /// TLS with a client certificate identity read from disk.
    TlsClientCertificate { identity: CertKeyIdentity },
    /// TLS 1.3 with an externally provisioned pre-shared key.
    #[cfg(feature = "psk")]
    TlsPsk {
        identity: String,
        key: PskKeyMaterial,
        exchange: PskKeyExchangeMode,
        groups: Vec<PskDheKeSupportedGroup>,
    },
}

/// Neutral security inputs collected from an executable's parsed CLI.
///
/// Each executable fills this from its own clap struct;
/// [`CliSecurity::from_cli_inputs`] owns the decision logic so it stays
/// identical across executables.
#[derive(Debug, Clone, Default)]
pub struct CliSecurityInputs {
    pub use_tls: bool,
    pub shared_secret: Option<String>,
    pub client_certificate: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    #[cfg(feature = "psk")]
    pub psk: Option<CliPskInputs>,
}

/// TLS 1.3 PSK inputs collected from an executable's parsed CLI.
#[cfg(feature = "psk")]
#[derive(Debug, Clone)]
pub struct CliPskInputs {
    pub identity: String,
    pub key: PskKeyMaterial,
    pub exchange: PskKeyExchangeMode,
    pub groups: Vec<PskDheKeSupportedGroup>,
}

#[derive(Debug, Clone)]
pub struct CertKeyIdentity {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
}

impl CertKeyIdentity {
    #[must_use]
    pub fn new(certificate_path: impl Into<PathBuf>, private_key_path: impl Into<PathBuf>) -> Self {
        Self {
            certificate_path: certificate_path.into(),
            private_key_path: private_key_path.into(),
        }
    }

    pub(crate) fn extend_watched_paths(&self, paths: &mut Vec<PathBuf>) {
        paths.push(self.certificate_path.clone());
        paths.push(self.private_key_path.clone());
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PskKeyExchangeMode {
    PskDhe,
    PskOnly,
}

/// PSK bytes as they are supplied by each executable's CLI contract.
#[derive(Debug, Clone)]
pub enum PskKeyMaterial {
    Raw(Vec<u8>),
    StandardBase64(String),
}

impl PskKeyMaterial {
    #[cfg(feature = "psk")]
    pub(crate) fn into_bytes(self) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Raw(bytes) => Ok(bytes),
            Self::StandardBase64(value) => base64::engine::general_purpose::STANDARD
                .decode(value)
                .context("--psk-key must be standard base64-encoded PSK bytes"),
        }
    }
}
