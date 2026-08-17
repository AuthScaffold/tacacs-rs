//! Linux implementation of the `session-wrapper` binary.
//!
//! This module glues together CLI parsing, the process lifecycle code, the
//! allowlist, and the async TACACS+-backed seccomp notification supervisor.
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
//! | [`supervisor`]     | Async notification loop, IPC authorization.           |
//!
//! # Fork safety and the tokio runtime
//!
//! Linux `fork(2)` is not safe to call while a multi-threaded runtime is running.
//! Only the calling thread survives in the child process. The locks that other
//! threads held remain permanently acquired. This module creates the tokio runtime
//! **after** `spawn_session` returns. At that point, the fork already happened,
//! and the child process already called `exec`. The child never sees the runtime.
#![allow(unsafe_code)]

#[path = "cli.rs"]
mod cli;
mod allowlist;
mod process;
mod process_reader;
mod seccomp;
mod deny;
mod supervisor;

use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

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
/// # Execution order
///
/// 1. Load (or default) the exec allowlist.
/// 2. Fork the child via `spawn_session` — no tokio runtime must exist here.
/// 3. Build the tokio runtime **after** the fork.
/// 4. Run the async supervisor inside `block_on`.
///
/// The runtime is created after the fork so that the child process never
/// inherits tokio's thread pool or I/O driver state (see module-level note on
/// fork safety).
fn orchestrate_session(cli: &Cli, service_endpoint: &IpcEndpoint) -> anyhow::Result<()> {
    log::info!("session-wrapper starting for user {} via {:?}", cli.user, service_endpoint);

    // Build the allowlist before forking.  Reading a file is safe here and
    // avoids doing I/O in the supervisor's async context.
    let allowlist = Arc::new(match &cli.allowlist {
        Some(path) => Allowlist::load(path)
            .with_context(|| format!("failed to load allowlist from {}", path.display()))?,
        None => Allowlist::default_only(),
    });

    // Fork the session child.  No tokio runtime must be alive at this point.
    let session = process::spawn_session(process::ChildProcessConfig {
        command: cli.command.clone(),
        user: cli.user.clone(),
        uid: cli.user_uid,
        gid: cli.user_gid,
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

    let config = Arc::new(SupervisorConfig {
        user: cli.user.clone(),
        port: cli.port.clone(),
        rem_addr: cli.rem_addr.clone(),
        fail_policy: cli.fail_policy,
        service_endpoint: service_endpoint.clone(),
        authorization_timeout: Duration::from_millis(cli.authorization_timeout_ms),
        privilege_level: u32::from(cli.privilege_level),
    });

    // Build the tokio runtime AFTER the fork.  Two worker threads are enough
    // because the main async work is: (a) the dispatch loop and (b) concurrent
    // per-notification handler tasks.  The blocking notification receiver runs
    // in a dedicated OS thread (not in the tokio thread pool).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to create tokio runtime for supervisor")?;

    rt.block_on(run_supervisor(&session, allowlist, config))
        .context("session supervisor failed")
}
