mod cli;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod seccomp;

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

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let listener_fd = seccomp::install_filter(cli.intercept_fork)
            .context("failed to install session-wrapper seccomp filter")?;
        log::debug!("Installed seccomp filter with listener fd {listener_fd}");
        orchestrate_session(cli, &service_endpoint);
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = service_endpoint;
        anyhow::bail!(
            "session-wrapper seccomp listener is currently supported on Linux x86_64 only"
        );
    }

    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn orchestrate_session(cli: &Cli, service_endpoint: &IpcEndpoint) {
    log::info!(
        "session-wrapper orchestration stub for user {} via {:?}",
        cli.user,
        service_endpoint
    );
    if let Some((command, args)) = cli.command.split_first() {
        authorization_stub(command, args, &cli.user, service_endpoint);
    } else {
        authorization_stub(&cli.shell.to_string_lossy(), &[], &cli.user, service_endpoint);
    }
    log::debug!("Parsed session-wrapper arguments: {cli:?}");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn authorization_stub(command: &str, args: &[String], user: &str, service_endpoint: &IpcEndpoint) {
    log::info!(
        "authorization stub: user={user} command={command} args={args:?} endpoint={service_endpoint:?}"
    );
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);
    run(&cli)
}
