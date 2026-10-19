#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu"),
    all(target_os = "windows", target_env = "msvc")
)))]
compile_error!("tacon supports Linux GNU and Windows MSVC only");

mod backend;
mod batch;
mod cli;
mod commands;
mod config;
mod connection;

use std::path::Path;

use anyhow::bail;
use clap::Parser;

use tacacsrs_config::TacacsPlusServerType;
use tacacsrs_config::prepare::PrepareOptions;

use backend::Backend;
use cli::{Cli, Command};
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

/// Runs the requested TACACS+ command against the resolved backend.
async fn execute_command(backend: &Backend, command: &Command) -> anyhow::Result<()> {
    log::info!("Running command: {command:?}");

    match command {
        Command::Accounting {
            args,
            cmd,
            cmd_args,
        } => {
            let operation = commands::accounting::accounting_operation(
                &args.user,
                &args.port,
                &args.rem_addr,
                cmd,
                cmd_args.as_ref(),
            );
            let response = backend.accounting(&operation).await?;
            println!("Received accounting response: {response:#?}");
        }

        Command::Authentication {
            args,
            password_stdin,
            privilege_level,
        } => {
            let password = commands::authentication::read_password(*password_stdin)?;
            let operation =
                commands::authentication::pap_operation(args, *privilege_level, password)?;
            let response = backend.pap_authentication(&operation).await?;
            println!("Received PAP authentication response: {response:#?}");
        }

        Command::Authorization {
            args,
            authentication_context,
            privilege_level,
            mode,
        } => {
            let operation = commands::authorization::authorization_operation(
                args,
                *privilege_level,
                *authentication_context,
                mode,
            )?;
            let response = backend.authorization(&operation).await?;
            println!("Received authorization response: {response:#?}");
        }

        Command::Batch { .. } => {
            // Batch mode is handled separately in run() before this function is called.
            unreachable!("Batch commands are handled by run_batch_mode before execute_command");
        }
        Command::DumpYangConfig => {
            unreachable!("dump-yang-config is handled in run() before execute_command");
        }
    }

    Ok(())
}

/// Builds the execution backend for a single AAA command.
///
/// On Linux, `--service-endpoint` selects the agent IPC channel. Otherwise the
/// command uses a direct connection: dedicated or adaptive single-connection,
/// depending on `--dedicated` and the resolved server configuration.
async fn build_backend(cli: &Cli, command: &Command) -> anyhow::Result<Backend> {
    #[cfg(target_os = "linux")]
    if let Some(endpoint) = cli.service_endpoint.as_deref() {
        return Ok(Backend::Service(backend::connect_service(endpoint).await?));
    }

    let server = config::resolve_server_for_command(cli, command)?;
    let options = PrepareOptions::default().with_certificate_verification(
        if cli.insecure_disable_certificate_verification {
            tacacsrs_networking::CertificateVerification::DisabledForDevelopment
        } else {
            tacacsrs_networking::CertificateVerification::Required
        },
    );

    let connection = if cli.dedicated {
        // Dedicated mode uses a minimal TCP or TLS connection with no background
        // tasks or session multiplexing.
        log::info!("Running in dedicated connection mode");
        establish_dedicated_connection(&server, options).await?
    } else {
        establish_connection(&server, options).await?
    };

    Ok(Backend::Direct(connection))
}

/// Runs the CLI in batch mode with requests from a JSON file.
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

    #[cfg(target_os = "linux")]
    if let Some(ref endpoint) = cli.service_endpoint {
        let results = batch::execute_batch_via_service(endpoint, &batch_file).await?;
        return finish_batch(&results);
    }

    let required_type = batch_file
        .required_server_type()
        .unwrap_or(TacacsPlusServerType::ACCOUNTING);
    let server_config = config::resolve_server_for_type(cli, required_type)?;
    let options = PrepareOptions::default().with_certificate_verification(
        if cli.insecure_disable_certificate_verification {
            tacacsrs_networking::CertificateVerification::DisabledForDevelopment
        } else {
            tacacsrs_networking::CertificateVerification::Required
        },
    );
    let results = batch::execute_batch(&server_config, cli.dedicated, &batch_file, options).await?;

    finish_batch(&results)
}

fn finish_batch(results: &[batch::RequestResult]) -> anyhow::Result<()> {
    batch::print_results_summary(results);

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
/// - A command run fails
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

    let backend = build_backend(&cli, &cli.command).await?;
    execute_command(&backend, &cli.command).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli).await
}
