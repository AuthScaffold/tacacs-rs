#[path = "cli.rs"]
mod cli;
mod process;
mod seccomp;

use std::process::ExitCode;
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

pub(crate) fn run() -> ExitCode {
    match try_run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

fn try_run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);

    let service_endpoint = IpcEndpoint::from_str(&cli.service_endpoint).with_context(|| {
        format!("Invalid service endpoint for session-wrapper: {}", cli.service_endpoint)
    })?;

    orchestrate_session(&cli, &service_endpoint)?;

    Ok(())
}

fn orchestrate_session(cli: &Cli, service_endpoint: &IpcEndpoint) -> anyhow::Result<()> {
    log::info!(
        "session-wrapper orchestration stub for user {} via {:?}",
        cli.user,
        service_endpoint
    );
    let (command, args) = cli
        .command
        .split_first()
        .context("missing command to authorize")?;
    authorization_stub(command, args, &cli.user, service_endpoint)?;
    log::debug!("Parsed session-wrapper arguments: {cli:?}");

    let session = process::spawn_session(process::ChildProcessConfig {
        shell: cli.shell.clone(),
        user: cli.user.clone(),
        uid: cli.user_uid,
        gid: cli.user_gid,
        intercept_fork: cli.intercept_fork,
    })
    .context("failed to spawn session process")?;

    log::debug!(
        "Spawned child {} with seccomp notification fd {} and control fd {}",
        session.child_pid(),
        session.notification_fd(),
        session.control_socket_fd()
    );
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn authorization_stub(
    command: &str,
    args: &[String],
    user: &str,
    service_endpoint: &IpcEndpoint,
) -> anyhow::Result<()> {
    log::info!(
        "authorization stub: user={user} command={command} args={args:?} endpoint={service_endpoint:?}"
    );
    Ok(())
}
