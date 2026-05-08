mod cli;

use std::str::FromStr;

use anyhow::Context;
use clap::Parser;
use tacacsrs_agent_client::IpcEndpoint;

use cli::Cli;

/// Initializes the logger based on verbosity level.
fn init_logger(verbose: u8) {
    let level = match verbose {
        0 => return,
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

fn run(cli: &Cli) -> anyhow::Result<()> {
    let service_endpoint = IpcEndpoint::from_str(&cli.service_endpoint).with_context(|| {
        format!("Invalid service endpoint for session-wrapper: {}", cli.service_endpoint)
    })?;

    orchestrate_session(cli, &service_endpoint);
    Ok(())
}

fn orchestrate_session(cli: &Cli, service_endpoint: &IpcEndpoint) {
    log::info!(
        "session-wrapper orchestration stub for user {} via {:?}",
        cli.user,
        service_endpoint
    );
    log::debug!("Parsed session-wrapper arguments: {cli:?}");
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);
    run(&cli)
}
