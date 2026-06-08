mod batch;
mod cli;
mod commands;
mod config;
mod connection;

use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, Context};
use clap::Parser;
use tacacsrs_agent_client::{AccountingOperation, IpcEndpoint, ServiceClient};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerType};
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_networking::{ClientSession, ConnectOptions};

use cli::{Cli, Command};
use commands::accounting::send_accounting_request;
use connection::{establish_connection, establish_dedicated_connection};

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
async fn execute_command(command: &Command, session: ClientSession) -> anyhow::Result<()> {
    log::info!("Executing command: {command:?}");

    match command {
        Command::Accounting {
            args,
            cmd,
            cmd_args,
        } => {
            send_accounting_request(
                session,
                &args.user,
                &args.port,
                &args.rem_addr,
                cmd,
                cmd_args.as_ref(),
                TacacsFlags::empty(),
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
        Command::DumpYangConfig => {
            unreachable!("dump-yang-config is handled in run() before execute_command");
        }
    }

    Ok(())
}

async fn execute_command_via_service(endpoint: &str, command: &Command) -> anyhow::Result<()> {
    let endpoint = IpcEndpoint::from_str(endpoint).context("Invalid service endpoint")?;
    let client = ServiceClient::connect(endpoint)
        .await
        .context("Failed to connect to TACACS+ service")?;

    match command {
        Command::Accounting {
            args,
            cmd,
            cmd_args,
        } => {
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
        Command::DumpYangConfig => {
            unreachable!("dump-yang-config is handled in run() before service execution")
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

    let results = if let Some(ref endpoint) = cli.service_endpoint {
        batch::execute_batch_via_service(endpoint, &batch_file).await?
    } else {
        let required_type = batch_file
            .required_server_type()
            .unwrap_or(TacacsPlusServerType::ACCOUNTING);
        let server_config = config::resolve_server_for_type(cli, required_type)?;
        let options = ConnectOptions::default()
            .with_certificate_verification_disabled(cli.insecure_disable_certificate_verification);
        batch::execute_batch(&server_config, cli.dedicated, &batch_file, &options).await?
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

    match &cli.command {
        Command::DumpYangConfig => {
            println!("{}", config::render_yang_config(&cli)?);
            return Ok(());
        }
        Command::Batch { file } => {
            log::info!("Running in batch mode with file: {file}");
            return run_batch_mode(&cli, Path::new(file)).await;
        }
        Command::Accounting { .. }
        | Command::Authentication { .. }
        | Command::Authorization { .. } => {}
    }

    if let Some(ref endpoint) = cli.service_endpoint {
        return execute_command_via_service(endpoint, &cli.command).await;
    }

    let server_config = config::resolve_server_for_command(&cli, &cli.command)?;
    let connect_options = ConnectOptions::default()
        .with_certificate_verification_disabled(cli.insecure_disable_certificate_verification);

    // Dedicated connection mode: minimal one-shot connection (TCP or TLS) per
    // request, no background tasks, no session multiplexing.
    if cli.dedicated {
        return execute_command_dedicated(&server_config, &connect_options, &cli.command).await;
    }

    let connection = establish_connection(&server_config, &connect_options).await?;
    let session = connection
        .create_session()
        .await
        .context("Failed to create TACACS+ session")?;

    execute_command(&cli.command, session).await
}

/// Executes the command using a dedicated connection — a minimal one-shot
/// TCP connection with no background tasks or session multiplexing.
async fn execute_command_dedicated(
    server: &TacacsPlusServer,
    options: &ConnectOptions,
    command: &Command,
) -> anyhow::Result<()> {
    log::info!("Running in dedicated connection mode");

    match command {
        Command::Accounting {
            args,
            cmd,
            cmd_args,
        } => {
            let connection = establish_dedicated_connection(server, options).await?;
            let session = connection
                .create_session()
                .await
                .context("Failed to create TACACS+ session")?;

            let result = send_accounting_request(
                session,
                &args.user,
                &args.port,
                &args.rem_addr,
                cmd,
                cmd_args.as_ref(),
                TacacsFlags::empty(),
            )
            .await
            .context("Dedicated accounting request failed")?;

            log::info!("Received accounting response: {result:?}");
        }

        Command::Authentication { .. } => {
            bail!("Authentication is not yet implemented");
        }
        Command::Authorization { .. } => {
            bail!("Authorization is not yet implemented");
        }
        Command::Batch { .. } => {
            unreachable!("Batch is handled before this point");
        }
        Command::DumpYangConfig => {
            unreachable!("dump-yang-config is handled in run() before dedicated execution");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli).await
}
