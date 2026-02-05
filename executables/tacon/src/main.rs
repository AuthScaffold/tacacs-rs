mod batch;
mod cli;
mod commands;
mod connection;

use std::path::Path;

use anyhow::{bail, Context};
use clap::Parser;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_networking::session::Session;

use cli::{Cli, Command};
use commands::accounting::send_accounting_request;
use connection::establish_connection;

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

/// Executes the requested TACACS+ command
async fn execute_command(command: &Command, session: &Session) -> anyhow::Result<()> {
    log::info!("Executing command: {command:?}");

    match command {
        Command::Accounting {
            args,
            cmd,
            cmd_args,
            custom_flag_1,
            custom_flag_2,
            session_id: _,
        } => {
            let mut custom_flags = TacacsFlags::empty();
            if *custom_flag_1 {
                custom_flags |= TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1;
            }
            if *custom_flag_2 {
                custom_flags |= TacacsFlags::TAC_PLUS_CUSTOM_FLAG_2;
            }

            send_accounting_request(
                session,
                &args.user,
                &args.port,
                &args.rem_addr,
                cmd,
                cmd_args.as_ref(),
                custom_flags,
            )
            .await?;
        }

        Command::Authentication { args: _ } => {
            log::info!("Authentication command not yet implemented");
            println!("Authentication command not yet implemented");
        }

        Command::Authorization { args: _ } => {
            log::info!("Authorization command not yet implemented");
            println!("Authorization command not yet implemented");
        }

        Command::Batch { .. } => {
            // Batch mode is handled separately in run() before this function is called
            unreachable!("Batch command should be handled before execute_command");
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
    let results = batch::execute_batch(cli, connection, &batch_file).await?;

    batch::print_results_summary(&results);

    // Return error if any requests failed
    let failed_count = results.iter().filter(|r| r.result.is_err()).count();
    if failed_count > 0 {
        bail!("{failed_count} request(s) failed");
    }

    Ok(())
}

/// Main application entry point
///
/// # Errors
///
/// Returns an error if:
/// - Connection to the TACACS+ server fails
/// - TLS configuration is invalid
/// - Command execution fails
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    init_logger(cli.verbose);

    // Handle batch subcommand separately
    if let Command::Batch { file } = &cli.command {
        log::info!("Running in batch mode with file: {file}");
        return run_batch_mode(&cli, Path::new(file)).await;
    }

    let connection = establish_connection(&cli).await?;

    let custom_session_id = cli.command.session_id();
    let session = connection
        .create_session_optional_id(custom_session_id)
        .await
        .context("Failed to create TACACS+ session")?;

    if let Some(sid) = custom_session_id {
        log::info!("Using custom session ID: {sid}");
    }

    execute_command(&cli.command, &session).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli).await
}
