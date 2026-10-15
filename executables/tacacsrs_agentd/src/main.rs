#![allow(clippy::doc_markdown)]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-agentd supports Linux GNU only");

use anyhow::Context;
use clap::Parser;

mod cli;
mod client_api_listener;
mod config_filter;
mod credential_provider;
mod host_integration;
mod local_services;
mod signals;
mod startup;
mod statistics;
mod supervision;

use crate::cli::Cli;

/// Initializes the logger based on verbosity level.
///
/// With the `console` feature and `tokio_unstable`, the daemon uses the tokio-console
/// tracing subscriber instead of `env_logger`. This subscriber gives real-time
/// async runtime profiling with the `tokio-console` tool.
#[cfg(all(feature = "console", tokio_unstable))]
fn init_logger(_verbose: u8) {
    console_subscriber::init();
}

/// Initializes the logger based on verbosity level.
#[cfg(not(all(feature = "console", tokio_unstable)))]
fn init_logger(verbose: u8) {
    #[cfg(feature = "console")]
    eprintln!("Tokio Console profiling is disabled. Rebuild with RUSTFLAGS=\"--cfg tokio_unstable\" to enable it.");
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

/// Starts the central TACACS+ client service process.
///
/// The service listens on the configured local IPC endpoint. It maintains
/// persistent upstream TACACS+ connections with ordered failover. It stops in
/// an orderly manner when it receives a termination signal.
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cli.worker_threads.get())
        .enable_all()
        .build()
        .context("Failed to build the Tokio runtime")?;

    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    init_logger(cli.verbose);
    let signals = signals::ProcessSignals::register()?;
    supervision::run_until(cli, signals.wait()).await
}
