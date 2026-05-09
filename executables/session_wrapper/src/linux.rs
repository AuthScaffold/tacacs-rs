//! Linux implementation of the `session-wrapper` binary.
//!
//! This module glues together CLI parsing, the process lifecycle code, the
//! allowlist, and the real TACACS+-backed seccomp notification supervisor.
//!
//! # Module layout
//!
//! | Module             | Responsibility                                        |
//! |--------------------|-------------------------------------------------------|
//! | [`cli`]            | CLI argument parsing (clap).                          |
//! | [`process`]        | Fork/exec lifecycle, seccomp fd hand-off.             |
//! | [`seccomp`]        | BPF filter construction.                              |
//! | [`allowlist`]      | Fast-path allow set (O(1) path lookup).               |
//! | [`process_reader`] | Read exec args from `/proc/[pid]/mem` via `pread`.   |
//! | [`supervisor`]     | Notification loop, IPC authorization, kernel responses|
#![allow(unsafe_code)]

#[path = "cli.rs"]
mod cli;
mod allowlist;
mod process;
mod process_reader;
mod seccomp;
mod supervisor;

use std::process::ExitCode;
use std::str::FromStr;

use anyhow::Context;
use clap::Parser;
use tacacsrs_agent_client::IpcEndpoint;

use allowlist::Allowlist;
use cli::Cli;
use supervisor::{SupervisorConfig, run_supervisor};

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

/// Runs the Linux `session-wrapper` entrypoint and converts errors to process exit status.
pub(crate) fn run() -> ExitCode {
    match try_run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

/// Parses CLI arguments and starts the session orchestration flow.
fn try_run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);

    let service_endpoint = IpcEndpoint::from_str(&cli.service_endpoint).with_context(|| {
        format!("Invalid service endpoint for session-wrapper: {}", cli.service_endpoint)
    })?;

    orchestrate_session(&cli, &service_endpoint)?;

    Ok(())
}

/// Wires together allowlist loading, child process creation, and supervision.
///
/// This is the top-level entry point that converts CLI options into the
/// runtime configuration consumed by the supervisor loop.
fn orchestrate_session(cli: &Cli, service_endpoint: &IpcEndpoint) -> anyhow::Result<()> {
    log::info!("session-wrapper starting for user {} via {:?}", cli.user, service_endpoint);

    // Build the allowlist. If the operator supplied a config file, load it
    // (merging with the built-in defaults). Otherwise, use built-ins only.
    let allowlist = match &cli.allowlist {
        Some(path) => Allowlist::load(path)
            .with_context(|| format!("failed to load allowlist from {}", path.display()))?,
        None => Allowlist::default_only(),
    };

    let session = process::spawn_session(process::ChildProcessConfig {
        shell: cli.shell.clone(),
        user: cli.user.clone(),
        uid: cli.user_uid,
        gid: cli.user_gid,
        intercept_fork: cli.intercept_fork,
    })
    .context("failed to spawn session process")?;

    log::debug!(
        "spawned child {} (pgid {}, sid {}) with seccomp notification fd {} and control fd {}",
        session.child_pid(),
        session.child_process_group_id(),
        session.child_session_id(),
        session.notification_fd(),
        session.control_socket_fd()
    );

    let config = SupervisorConfig {
        user: cli.user.clone(),
        port: cli.port.clone(),
        rem_addr: cli.rem_addr.clone(),
        fail_policy: cli.fail_policy,
        service_endpoint: service_endpoint.clone(),
    };

    run_supervisor(&session, &allowlist, &config).context("session supervisor failed")
}
