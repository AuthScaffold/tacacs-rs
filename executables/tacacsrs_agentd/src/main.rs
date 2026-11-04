#![allow(clippy::doc_markdown)]

#[cfg(not(all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))))]
compile_error!("tacacsrs-agentd supports Linux GNU or musl only");

use anyhow::Context;
use clap::{CommandFactory, FromArgMatches};

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
mod kubesonic;

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
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    let environment = if cli.kubesonic {
        for id in matches.ids() {
            if id.as_str() != "kubesonic"
                && matches.value_source(id.as_str()) == Some(clap::parser::ValueSource::CommandLine)
                && cli::Cli::command()
                    .get_arguments()
                    .any(|argument| argument.get_id() == id)
            {
                anyhow::bail!(
                    "--kubesonic uses AAAAGENT_ inputs. Runtime CLI arguments are not supported"
                );
            }
        }
        Some(tacacsrs_kubesonic::environment::Environment::from_process()?)
    } else {
        None
    };
    if let Some(environment) = &environment {
        env_filter::Builder::new()
            .try_parse(&environment.process.log_filter)
            .map_err(|_| anyhow::anyhow!("AAAAGENT_LOG_FILTER is invalid"))?;
        let style = match environment.process.log_style.as_str() {
            "auto" => env_logger::WriteStyle::Auto,
            "always" => env_logger::WriteStyle::Always,
            "never" => env_logger::WriteStyle::Never,
            _ => anyhow::bail!("AAAAGENT_LOG_STYLE is invalid"),
        };
        env_logger::Builder::new()
            .parse_filters(&environment.process.log_filter)
            .write_style(style)
            .try_init()
            .context("Failed to initialize KubeSONiC logging")?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            environment
                .as_ref()
                .map_or(cli.worker_threads.get(), |input| input.process.worker_threads.get()),
        )
        .enable_all()
        .build()
        .context("Failed to build the Tokio runtime")?;

    runtime.block_on(run(cli, environment))
}

async fn run(
    cli: Cli,
    environment: Option<tacacsrs_kubesonic::environment::Environment>,
) -> anyhow::Result<()> {
    if environment.is_none() {
        init_logger(cli.verbose);
    }
    let signals = signals::ProcessSignals::register()?;
    supervision::run_until(cli, environment, signals.wait()).await
}
