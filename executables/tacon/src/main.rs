mod batch;
mod cli;
mod commands;
mod connection;

use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, Context};
use clap::Parser;
use tacacsrs_agent_client::{AccountingOperation, IpcEndpoint, ServiceClient};
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
            unreachable!("Batch commands are handled by run_batch_mode before execute_command");
        }
    }

    Ok(())
}

fn ensure_service_mode_accounting_supported(
    custom_flag_1: bool,
    custom_flag_2: bool,
    session_id: Option<u32>,
) -> anyhow::Result<()> {
    if custom_flag_1 || custom_flag_2 || session_id.is_some() {
        anyhow::bail!(
            "Central TACACS+ service mode does not support custom TACACS+ flags or client-specified session IDs"
        );
    }

    Ok(())
}

async fn execute_command_via_service(cli: &Cli, command: &Command) -> anyhow::Result<()> {
    let endpoint = cli
        .service_endpoint
        .as_deref()
        .context("Service endpoint is required for service mode")?;
    let endpoint = IpcEndpoint::from_str(endpoint).context("Invalid service endpoint")?;
    let client = ServiceClient::new(endpoint);

    match command {
        Command::Accounting {
            args,
            cmd,
            cmd_args,
            custom_flag_1,
            custom_flag_2,
            session_id,
        } => {
            ensure_service_mode_accounting_supported(*custom_flag_1, *custom_flag_2, *session_id)?;
            let response = client
                .send_accounting(AccountingOperation {
                    user: args.user.clone(),
                    port: args.port.clone(),
                    remote_address: args.rem_addr.clone(),
                    command: cmd.clone(),
                    command_arguments: cmd_args.clone().unwrap_or_default(),
                })
                .await?;

            println!("Received accounting response: {response:#?}");
        }
        Command::Authentication { .. } => {
            log::info!("Authentication command not yet implemented");
            println!("Authentication command not yet implemented");
        }
        Command::Authorization { .. } => {
            log::info!("Authorization command not yet implemented");
            println!("Authorization command not yet implemented");
        }
        Command::Batch { .. } => {
            unreachable!(
                "Batch commands are handled by run_batch_mode before execute_command_via_service"
            )
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

    let results = if cli.service_endpoint.is_some() {
        batch::execute_batch_via_service(cli, &batch_file).await?
    } else {
        let connection = establish_connection(cli).await?;
        batch::execute_batch(cli, connection, &batch_file).await?
    };

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

    if cli.service_endpoint.is_some() {
        return execute_command_via_service(&cli, &cli.command).await;
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

#[cfg(test)]
mod tests {
    use super::ensure_service_mode_accounting_supported;

    #[test]
    fn test_service_mode_rejects_custom_flags_and_session_ids() {
        assert!(ensure_service_mode_accounting_supported(true, false, None).is_err());
        assert!(ensure_service_mode_accounting_supported(false, true, None).is_err());
        assert!(ensure_service_mode_accounting_supported(false, false, Some(7)).is_err());
        assert!(ensure_service_mode_accounting_supported(false, false, None).is_ok());
    }
}
