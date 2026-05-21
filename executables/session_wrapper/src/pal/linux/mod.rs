//! Linux `x86_64` PAL backend for the `session-wrapper` binary.
//!
//! This module glues together the process lifecycle code, seccomp policy,
//! process memory reader, and async TACACS+-backed notification supervisor.
//!
//! # Module layout
//!
//! | Module             | Responsibility                                        |
//! |--------------------|-------------------------------------------------------|
//! | [`process`]        | Fork/exec lifecycle, seccomp fd hand-off.             |
//! | [`seccomp`]        | BPF filter construction.                              |
//! | [`process_reader`] | Read exec args from `/proc/[pid]/mem` via `pread`.   |
//! | [`supervisor`]     | Async notification loop, IPC authorization.           |
//!
//! # Fork safety and the tokio runtime
//!
//! Linux `fork(2)` is not safe to call while a multi-threaded runtime is
//! running because only the calling thread survives in the child, leaving
//! other threads' locks permanently acquired.  This module creates the tokio
//! runtime **after** `spawn_session` returns (i.e. after the fork has already
//! happened and the child has exec'd).  The child never sees the runtime.
#![allow(unsafe_code)]

mod process;
mod process_reader;
mod seccomp;
mod supervisor;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tacacsrs_agent_client::IpcEndpoint;

use crate::allowlist::Allowlist;
use crate::cli::Cli;

use supervisor::{SupervisorConfig, run_supervisor};

pub(crate) fn run_session(cli: Cli, service_endpoint: IpcEndpoint) -> anyhow::Result<()> {
    let Cli {
        user,
        user_uid,
        user_gid,
        service_endpoint: _,
        fail_policy,
        authorization_timeout_ms,
        privilege_level,
        allowlist,
        port,
        rem_addr,
        verbose: _,
        command,
    } = cli;

    log::info!("session-wrapper starting for user {user} via {service_endpoint:?}");

    let allowlist = Arc::new(match &allowlist {
        Some(path) => Allowlist::load(path)
            .with_context(|| format!("failed to load allowlist from {}", path.display()))?,
        None => Allowlist::default_only(),
    });

    let session = process::spawn_session(process::ChildProcessConfig {
        command,
        user: user.clone(),
        uid: user_uid,
        gid: user_gid,
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
        user,
        port,
        rem_addr,
        fail_policy,
        service_endpoint,
        authorization_timeout: Duration::from_millis(authorization_timeout_ms),
        privilege_level: u32::from(privilege_level),
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to create tokio runtime for supervisor")?;

    rt.block_on(run_supervisor(&session, allowlist, config))
        .context("session supervisor failed")
}
