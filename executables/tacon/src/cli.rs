use clap::{ArgGroup, Parser, Subcommand};

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
        .args(["server_addr", "service_endpoint"])
))]
pub struct Cli {
    /// IP address and port of the TACACS+ server (e.g., "192.168.1.1:49")
    #[arg(short, long)]
    pub server_addr: Option<String>,

    /// IPC endpoint for the central TACACS+ client service
    #[arg(long, value_name = "PATH_OR_ADDR")]
    pub service_endpoint: Option<String>,

    /// Obfuscation key for encrypting TACACS+ messages
    #[arg(short = 'k', long, conflicts_with = "service_endpoint")]
    pub obfuscation_key: Option<String>,

    /// Use TLS for the connection
    #[arg(long, conflicts_with = "service_endpoint")]
    pub use_tls: bool,

    /// Path to client certificate file for TLS authentication
    #[arg(long, value_name = "FILE", requires = "client_key", conflicts_with = "service_endpoint")]
    pub client_certificate: Option<String>,

    /// Path to client private key file for TLS authentication
    #[arg(
        long,
        value_name = "FILE",
        requires = "client_certificate",
        conflicts_with = "service_endpoint"
    )]
    pub client_key: Option<String>,

    /// Dangerously disable TLS certificate verification for direct server connections.
    #[arg(long, requires = "use_tls", conflicts_with = "service_endpoint")]
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

    /// Use a minimal dedicated connection (no background tasks). Each
    /// request opens and closes its own TCP connection, rather than
    /// reusing connections managed by the central service. Useful for
    /// testing or simple one-off requests.
    #[arg(long, requires = "server_addr", conflicts_with = "service_endpoint")]
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

        /// Set `TAC_PLUS_CUSTOM_FLAG_1` (0x40) on the packet header
        #[arg(long)]
        custom_flag_1: bool,

        /// Set `TAC_PLUS_CUSTOM_FLAG_2` (0x80) on the packet header
        #[arg(long)]
        custom_flag_2: bool,

        /// Use a specific session ID instead of a randomly generated one
        #[arg(long)]
        session_id: Option<u32>,
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

impl Command {
    /// Returns the custom session ID from the command, if specified
    #[must_use]
    pub fn session_id(&self) -> Option<u32> {
        match self {
            Self::Accounting { session_id, .. } => *session_id,
            Self::Batch { .. } | Self::Authentication { .. } | Self::Authorization { .. } => None,
        }
    }
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
            "cert.pem",
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
}
