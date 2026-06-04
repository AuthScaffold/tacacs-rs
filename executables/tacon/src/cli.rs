use clap::{ArgGroup, Parser, Subcommand, ValueEnum};

/// Validation relaxation that loosens a specific YANG constraint.
///
/// Relaxations are opt-in; default (strict) validation never applies them.
#[derive(Debug, Clone, ValueEnum)]
pub enum ValidationRelaxation {
    /// Allow TLS and `shared-secret` to coexist on the same server.
    ///
    /// Intended as a migration aid for server implementations that have not
    /// yet cleanly removed shared-secret handling after enabling TLS.
    #[value(name = "allow-tls-with-shared-secret")]
    AllowTlsWithSharedSecret,

    /// Allow plain TCP without TLS or TACACS+ shared-secret obfuscation.
    #[value(name = "allow-plain-tcp-without-shared-secret")]
    AllowPlainTcpWithoutSharedSecret,
}

/// TACACS+ Client CLI
///
/// A command-line tool for interacting with TACACS+ servers,
/// supporting authentication, authorization, and accounting operations.
#[derive(Parser, Clone)]
#[command(name = "tacon", version, author)]
#[command(about = "TACACS+ client CLI", long_about = None)]
#[command(group(
    ArgGroup::new("transport_target")
        .required(true)
        .args(["server_addr", "service_endpoint", "config"])
))]
#[command(group(
    ArgGroup::new("certificate_verification_target")
        .args(["use_tls", "config"])
))]
pub struct Cli {
    /// IP address and port of the TACACS+ server (e.g., "192.168.1.1:49")
    #[arg(short, long)]
    pub server_addr: Option<String>,

    /// Path to a YANG JSON configuration file (ietf-system-tacacs-plus)
    #[arg(long, value_name = "FILE", conflicts_with_all = [
        "service_endpoint", "shared_secret", "use_tls",
        "client_certificate", "client_key",
    ])]
    pub config: Option<std::path::PathBuf>,

    /// IPC endpoint for the central TACACS+ client service
    #[arg(long, value_name = "PATH_OR_ADDR")]
    pub service_endpoint: Option<String>,

    /// Shared secret for TACACS+ message obfuscation
    #[arg(short = 'k', long, conflicts_with = "service_endpoint")]
    pub shared_secret: Option<String>,

    /// Use TLS for the connection
    #[arg(long, conflicts_with = "service_endpoint")]
    pub use_tls: bool,

    /// Path to a PEM- or DER-encoded client certificate file for TLS authentication
    #[arg(long, value_name = "FILE", requires = "client_key", conflicts_with = "service_endpoint")]
    pub client_certificate: Option<String>,

    /// Path to a PEM- or DER-encoded client private key file for TLS authentication
    #[arg(
        long,
        value_name = "FILE",
        requires = "client_certificate",
        conflicts_with = "service_endpoint"
    )]
    pub client_key: Option<String>,

    /// Dangerously disable TLS certificate verification for direct server connections.
    #[arg(long, requires = "certificate_verification_target", conflicts_with = "service_endpoint")]
    pub insecure_disable_certificate_verification: bool,

    /// PSK identity string sent to the server during the TLS 1.3 handshake
    #[cfg(feature = "psk")]
    #[arg(long, value_name = "IDENTITY", requires_all = ["use_tls", "psk_key"], conflicts_with_all = ["client_certificate", "client_key", "service_endpoint"])]
    pub psk_identity: Option<String>,

    /// Pre-shared key for TLS 1.3 PSK authentication
    #[cfg(feature = "psk")]
    #[arg(long, value_name = "KEY", requires_all = ["use_tls", "psk_identity"], conflicts_with_all = ["client_certificate", "client_key", "service_endpoint"])]
    pub psk_key: Option<String>,

    /// Increase verbosity level (-v, -vv, -vvv, -vvvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Apply a validation relaxation when loading or constructing configuration.
    ///
    /// May be repeated to enable multiple relaxations.
    /// Valid values: allow-tls-with-shared-secret, allow-plain-tcp-without-shared-secret
    #[arg(
        long,
        value_name = "RELAXATION",
        action = clap::ArgAction::Append,
        conflicts_with = "service_endpoint"
    )]
    pub validation_relaxation: Vec<ValidationRelaxation>,

    /// Use a minimal dedicated connection for each request. Each request
    /// opens and closes its own direct TCP or TLS connection to the server,
    /// instead of using a reused or multiplexed connection. Useful for
    /// testing or simple one-off requests.
    #[arg(long, conflicts_with = "service_endpoint")]
    pub dedicated: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Common arguments for TACACS+ requests
#[derive(Parser, Debug, Clone)]
pub struct RequestArgs {
    /// Username for the TACACS+ request
    #[arg(short, long)]
    pub user: String,

    /// Port identifier for the TACACS+ request (e.g., "tty0")
    #[arg(short, long)]
    pub port: String,

    /// Remote address of the client (e.g., "192.168.1.100")
    #[arg(short, long)]
    pub rem_addr: String,
}

/// Available TACACS+ operations
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Run in batch mode using commands from a file
    Batch {
        /// Path to the batch file containing TACACS+ requests
        file: String,
    },

    /// Send an accounting record
    Accounting {
        #[command(flatten)]
        args: RequestArgs,

        /// Command being executed (e.g., "show running-config")
        cmd: String,

        /// Additional arguments for the command
        #[arg(value_name = "ARG")]
        cmd_args: Option<Vec<String>>,
    },

    /// Perform authentication
    Authentication {
        #[command(flatten)]
        args: RequestArgs,
    },

    /// Perform authorization check
    Authorization {
        #[command(flatten)]
        args: RequestArgs,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn test_batch_subcommand_parses() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "batch",
            "batch_file.txt",
        ]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_user_port_remaddr_required_without_command() {
        // Without a subcommand, parsing fails (subcommand is required)
        let result = Cli::try_parse_from(["tacon", "--server-addr", "localhost:49"]);

        assert!(result.is_err());
    }

    #[test]
    fn test_accounting_requires_user_port_remaddr() {
        // Accounting without user/port/rem_addr fails at parse time
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "accounting",
            "test_cmd",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_accounting_parses_with_required_args() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "accounting",
            "--user",
            "testuser",
            "--port",
            "tty0",
            "--rem-addr",
            "192.168.1.100",
            "test_cmd",
        ]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_tls_requires_both_cert_and_key() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "--use-tls",
            "--client-certificate",
            "cert.der",
            "batch",
            "batch.txt",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_service_endpoint_parses_without_server_addr() {
        let result = Cli::try_parse_from([
            "tacon",
            "--service-endpoint",
            "/run/tacacs.sock",
            "accounting",
            "--user",
            "testuser",
            "--port",
            "tty0",
            "--rem-addr",
            "192.168.1.100",
            "test_cmd",
        ]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_config_allows_insecure_certificate_verification_flag() {
        let result = Cli::try_parse_from([
            "tacon",
            "--config",
            "config.json",
            "--insecure-disable-certificate-verification",
            "accounting",
            "--user",
            "testuser",
            "--port",
            "tty0",
            "--rem-addr",
            "192.168.1.100",
            "test_cmd",
        ]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_insecure_certificate_verification_requires_tls_or_config() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "--insecure-disable-certificate-verification",
            "accounting",
            "--user",
            "testuser",
            "--port",
            "tty0",
            "--rem-addr",
            "192.168.1.100",
            "test_cmd",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_dedicated_mode_parses_with_config() {
        let result = Cli::try_parse_from([
            "tacon",
            "--config",
            "config.json",
            "--dedicated",
            "batch",
            "batch_file.txt",
        ]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_server_addr_conflicts_with_service_endpoint() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "--service-endpoint",
            "/run/tacacs.sock",
            "batch",
            "batch.txt",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_validation_relaxation_single_value_parses() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "--validation-relaxation",
            "allow-tls-with-shared-secret",
            "batch",
            "batch.txt",
        ]);

        assert!(result.is_ok());
        let cli = result.unwrap();
        assert_eq!(cli.validation_relaxation.len(), 1);
        assert!(matches!(
            cli.validation_relaxation[0],
            ValidationRelaxation::AllowTlsWithSharedSecret
        ));
    }

    #[test]
    fn test_validation_relaxation_multiple_values_parse() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "--validation-relaxation",
            "allow-tls-with-shared-secret",
            "--validation-relaxation",
            "allow-plain-tcp-without-shared-secret",
            "batch",
            "batch.txt",
        ]);

        assert!(result.is_ok());
        let cli = result.unwrap();
        assert_eq!(cli.validation_relaxation.len(), 2);
        assert!(matches!(
            cli.validation_relaxation[0],
            ValidationRelaxation::AllowTlsWithSharedSecret
        ));
        assert!(matches!(
            cli.validation_relaxation[1],
            ValidationRelaxation::AllowPlainTcpWithoutSharedSecret
        ));
    }

    #[test]
    fn test_validation_relaxation_unknown_value_is_rejected() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "--validation-relaxation",
            "allow-everything",
            "batch",
            "batch.txt",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_validation_relaxation_absent_yields_empty_vec() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "batch",
            "batch.txt",
        ]);

        assert!(result.is_ok());
        assert!(result.unwrap().validation_relaxation.is_empty());
    }

    #[test]
    fn test_validation_relaxation_conflicts_with_service_endpoint() {
        let result = Cli::try_parse_from([
            "tacon",
            "--service-endpoint",
            "/run/tacacs.sock",
            "--validation-relaxation",
            "allow-tls-with-shared-secret",
            "batch",
            "batch.txt",
        ]);

        assert!(result.is_err());
    }
}
