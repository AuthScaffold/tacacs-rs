mod batch;
mod commands;

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_networking::{
    helpers::TlsConfigurationBuilder,
    session::Session,
    tcp_connection::{TcpConnection, TcpConnectionTrait},
    tls_connection::{TlsConnection, TLSConnectionTrait},
    traits::SessionManagementTrait,
};

use commands::accounting::send_accounting_request;

/// TACACS+ Client CLI
///
/// A command-line tool for interacting with TACACS+ servers,
/// supporting authentication, authorization, and accounting operations.
#[derive(Parser)]
#[command(name = "tacon", version, author)]
#[command(about = "TACACS+ client CLI", long_about = None)]
pub struct Cli {
    /// IP address and port of the TACACS+ server (e.g., "192.168.1.1:49")
    #[arg(short, long)]
    server_addr: String,

    /// Obfuscation key for encrypting TACACS+ messages
    #[arg(short = 'k', long)]
    obfuscation_key: Option<String>,

    /// Use TLS for the connection
    #[arg(long)]
    use_tls: bool,

    /// Path to client certificate file for TLS authentication
    #[arg(long, value_name = "FILE", requires = "client_key")]
    client_certificate: Option<String>,

    /// Path to client private key file for TLS authentication
    #[arg(long, value_name = "FILE", requires = "client_certificate")]
    client_key: Option<String>,

    /// Increase verbosity level (-v, -vv, -vvv, -vvvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Run in batch mode using commands from a file
    #[arg(short, long, value_name = "FILE")]
    batch: Option<String>,

    /// Username for the TACACS+ request
    #[arg(short, long, required_unless_present = "batch")]
    user: Option<String>,

    /// Port identifier for the TACACS+ request (e.g., "tty0")
    #[arg(short, long, required_unless_present = "batch")]
    port: Option<String>,

    /// Remote address of the client (e.g., "192.168.1.100")
    #[arg(short, long, required_unless_present = "batch")]
    rem_addr: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Available TACACS+ operations
#[derive(Subcommand, Debug)]
enum Command {
    /// Send an accounting record
    Accounting {
        /// Command being executed (e.g., "show running-config")
        cmd: String,

        /// Additional arguments for the command
        #[arg(value_name = "ARG")]
        cmd_args: Option<Vec<String>>,

        /// Set TAC_PLUS_CUSTOM_FLAG_1 (0x40) on the packet header
        #[arg(long)]
        custom_flag_1: bool,

        /// Set TAC_PLUS_CUSTOM_FLAG_2 (0x80) on the packet header
        #[arg(long)]
        custom_flag_2: bool,

        /// Use a specific session ID instead of a randomly generated one
        #[arg(long)]
        session_id: Option<u32>,
    },

    /// Perform authentication
    Authentication,

    /// Perform authorization check
    Authorization,
}

/// Represents an active TACACS+ connection (either plain TCP or TLS)
pub enum Connection {
    Tcp(Arc<TcpConnection>),
    Tls(Arc<TlsConnection>),
}

impl Connection {
    /// Creates a new session on this connection
    ///
    /// # Errors
    ///
    /// Returns an error if session creation fails on the underlying connection.
    pub async fn create_session(&self) -> anyhow::Result<Session> {
        match self {
            Self::Tcp(conn) => conn.create_session().await,
            Self::Tls(conn) => conn.create_session().await,
        }
    }

    /// Creates a session with a specific session ID on this connection
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID is already in use or if session creation fails.
    pub async fn create_session_with_id(&self, session_id: u32) -> anyhow::Result<Session> {
        match self {
            Self::Tcp(conn) => conn.create_session_with_id(session_id).await,
            Self::Tls(conn) => conn.create_session_with_id(session_id).await,
        }
    }

    /// Creates a session, optionally with a specific session ID
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID is already in use or if session creation fails.
    pub async fn create_session_optional_id(&self, session_id: Option<u32>) -> anyhow::Result<Session> {
        match session_id {
            Some(id) => self.create_session_with_id(id).await,
            None => self.create_session().await,
        }
    }
}

/// Initializes the logger based on verbosity level
fn init_logger(verbose: u8) {
    let level = match verbose {
        0 => return, // No logging requested
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

/// Establishes a connection to the TACACS+ server
async fn establish_connection(cli: &Cli) -> anyhow::Result<Connection> {
    let obfuscation_key = cli.obfuscation_key.as_ref().map(String::as_bytes);
    let tcp_stream = tacacsrs_networking::helpers::connect_tcp(&cli.server_addr)
        .await
        .context("Failed to establish TCP connection")?;

    if cli.use_tls {
        let client_cert = cli
            .client_certificate
            .as_ref()
            .context("TLS requires a client certificate")?;
        let client_key = cli
            .client_key
            .as_ref()
            .context("TLS requires a client key")?;

        let tls_config = Arc::new(
            TlsConfigurationBuilder::new()
                .with_client_auth_cert_files(client_cert, client_key)
                .await
                .context("Failed to load TLS certificates")?
                .with_certificate_verification_disabled(true)
                .build()
                .context("Failed to build TLS configuration")?,
        );

        let tls_stream = tacacsrs_networking::helpers::connect_tls(
            &tls_config,
            tcp_stream,
            "tacacsserver.local",
        )
        .await
        .context("Failed to establish TLS connection")?;

        let connection = Arc::new(TlsConnection::new(obfuscation_key));
        connection
            .run(tls_stream)
            .await
            .context("Failed to start TLS session manager")?;

        Ok(Connection::Tls(connection))
    } else {
        let connection = Arc::new(TcpConnection::new(obfuscation_key));
        connection
            .run(tcp_stream)
            .await
            .context("Failed to start TCP session manager")?;

        Ok(Connection::Tcp(connection))
    }
}

/// Executes the requested TACACS+ command
async fn execute_command(cli: &Cli, session: &Session) -> anyhow::Result<()> {
    let Some(command) = &cli.command else {
        return Ok(());
    };

    log::info!("Executing command: {command:?}");

    match command {
        Command::Accounting { cmd, cmd_args, custom_flag_1, custom_flag_2, session_id: _ } => {
            let user = cli.user.as_ref().context("User is required")?;
            let port = cli.port.as_ref().context("Port is required")?;
            let rem_addr = cli.rem_addr.as_ref().context("Remote address is required")?;

            let mut custom_flags = TacacsFlags::empty();
            if *custom_flag_1 {
                custom_flags |= TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1;
            }
            if *custom_flag_2 {
                custom_flags |= TacacsFlags::TAC_PLUS_CUSTOM_FLAG_2;
            }

            send_accounting_request(session, user, port, rem_addr, cmd, cmd_args.as_ref(), custom_flags).await?;
        }

        Command::Authentication => {
            log::info!("Authentication command not yet implemented");
            println!("Authentication command not yet implemented");
        }

        Command::Authorization => {
            log::info!("Authorization command not yet implemented");
            println!("Authorization command not yet implemented");
        }
    }

    Ok(())
}

/// Runs the CLI in batch mode, executing requests from a JSON file
///
/// # Errors
///
/// Returns an error if the batch file cannot be loaded or if connection fails.
async fn run_batch_mode(cli: &Cli, batch_path: &Path) -> anyhow::Result<()> {
    let batch_file = batch::load_batch_file(batch_path)?;

    println!(
        "Loaded batch file with {} requests (parallel: {})",
        batch_file.requests.len(),
        batch_file.metadata.parallel
    );

    let connection = establish_connection(cli).await?;
    let results = batch::execute_batch(&connection, &batch_file).await?;

    batch::print_results_summary(&results);

    // Return error if any requests failed
    let failed_count = results.iter().filter(|r| r.result.is_err()).count();
    if failed_count > 0 {
        bail!("{failed_count} request(s) failed");
    }

    Ok(())
}

/// Returns the custom session ID from the command, if specified
fn get_command_session_id(command: &Option<Command>) -> Option<u32> {
    match command {
        Some(Command::Accounting { session_id, .. }) => *session_id,
        Some(Command::Authentication) | Some(Command::Authorization) | None => None,
    }
}

/// Main application entry point
///
/// # Errors
///
/// Returns an error if:
/// - Connection to the TACACS+ server fails
/// - TLS configuration is invalid
/// - Command execution fails
/// - Batch mode is used with subcommands
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    init_logger(cli.verbose);

    // Validate batch mode usage
    if cli.batch.is_some() && cli.command.is_some() {
        bail!("--batch flag cannot be used with subcommands");
    }

    if let Some(batch_file) = &cli.batch {
        log::info!("Running in batch mode with file: {batch_file}");
        return run_batch_mode(&cli, Path::new(batch_file)).await;
    }

    let connection = establish_connection(&cli).await?;
    
    let custom_session_id = get_command_session_id(&cli.command);
    let session = connection
        .create_session_optional_id(custom_session_id)
        .await
        .context("Failed to create TACACS+ session")?;

    if let Some(sid) = custom_session_id {
        log::info!("Using custom session ID: {sid}");
    }

    execute_command(&cli, &session).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli).await
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
    fn test_batch_mode_conflicts_with_subcommand() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "--batch",
            "batch_file.txt",
            "accounting",
            "test_value",
        ]);

        // Parsing should succeed; conflict is checked at runtime
        assert!(result.is_ok());
    }

    #[test]
    fn test_user_port_remaddr_required_without_batch() {
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
    fn test_batch_mode_allows_missing_user_port_remaddr() {
        let result = Cli::try_parse_from([
            "tacon",
            "--server-addr",
            "localhost:49",
            "--batch",
            "batch_file.txt",
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
            "--batch",
            "batch.txt",
        ]);

        assert!(result.is_err());
    }
}
