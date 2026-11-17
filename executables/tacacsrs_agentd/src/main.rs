#![allow(clippy::doc_markdown)]

#[cfg(not(all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))))]
compile_error!("tacacsrs-agentd supports Linux GNU or musl only");

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
mod source_registry;
mod profiles;
mod process;
mod host_service;

use crate::cli::Cli;

/// Starts the central TACACS+ client service process.
///
/// The service listens on the configured local IPC endpoint. It maintains
/// persistent upstream TACACS+ connections with ordered failover. It stops in
/// an orderly manner when it receives a termination signal.
fn main() -> anyhow::Result<()> {
    let profile = profiles::select(Cli::parse())?;
    profile.process.logging.initialize()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(profile.process.worker_threads.get())
        .enable_all()
        .build()
        .context("Failed to build the Tokio runtime")?;

    runtime.block_on(run(profile))
}

async fn run(profile: profiles::SelectedProfile) -> anyhow::Result<()> {
    let signals = signals::ProcessSignals::register()?;
    supervision::run_until(profile, signals.wait()).await
}
