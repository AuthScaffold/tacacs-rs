#![allow(unsafe_code)]

#[path = "cli.rs"]
mod cli;
mod process;
mod seccomp;

use std::collections::HashSet;
use std::io;
use std::os::fd::RawFd;
use std::process::ExitCode;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context};
use clap::Parser;
use libseccomp::{ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use tacacsrs_agent_client::IpcEndpoint;

use cli::Cli;
use process::{ChildSetupStatus, SessionProcess};

const SUPERVISOR_POLL_TIMEOUT_MS: i32 = 250;
const SUPERVISOR_IDLE_SLEEP: Duration = Duration::from_millis(250);

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
        "Spawned child {} (pgid {}, sid {}) with seccomp notification fd {} and control fd {}",
        session.child_pid(),
        session.child_process_group_id(),
        session.child_session_id(),
        session.notification_fd(),
        session.control_socket_fd()
    );

    run_allow_all_supervisor(&session).context("temporary allow-all session supervisor failed")
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

fn run_allow_all_supervisor(session: &SessionProcess) -> anyhow::Result<()> {
    log::warn!("running temporary allow-all session supervisor for child {}", session.child_pid());

    session
        .signal_supervisor_ready()
        .context("failed to release child after supervisor setup")?;

    let mut tracked_pids = HashSet::from([session.child_pid()]);
    let mut has_child_processes = true;
    let mut notification_fd_open = true;
    let mut control_socket_open = true;

    while has_child_processes || !tracked_pids.is_empty() {
        let mut fds = [
            libc::pollfd {
                fd: if notification_fd_open {
                    session.notification_fd()
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if control_socket_open {
                    session.control_socket_fd()
                } else {
                    -1
                },
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
        ];

        if notification_fd_open || control_socket_open {
            poll_fds(&mut fds, SUPERVISOR_POLL_TIMEOUT_MS)?;
        } else {
            thread::sleep(SUPERVISOR_IDLE_SLEEP);
        }

        if control_socket_open
            && fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            match session
                .read_child_setup_status()
                .context("failed to read child setup status")?
            {
                ChildSetupStatus::ControlClosed => {
                    control_socket_open = false;
                    log::debug!(
                        "child {} closed setup control socket at exec boundary",
                        session.child_pid()
                    );
                }
                ChildSetupStatus::Failed(message) => {
                    bail!("child setup failed after supervisor ready: {message}");
                }
            }
        }

        let notification_events = fds[0].revents;
        if notification_fd_open && notification_events & libc::POLLIN != 0 {
            let pid = allow_one_notification(session.notification_fd())
                .context("failed to allow seccomp notification")?;
            tracked_pids.insert(pid);
        }
        if notification_fd_open && notification_events & (libc::POLLERR | libc::POLLNVAL) != 0 {
            bail!("seccomp notification fd reported unexpected poll events: {notification_events}");
        }
        if notification_fd_open && notification_events & libc::POLLHUP != 0 {
            notification_fd_open = false;
        }

        let reap_status = process::reap_available_children()?;
        has_child_processes = reap_status.has_children;

        for reaped in reap_status.reaped {
            tracked_pids.remove(&reaped.pid);
            log::debug!("reaped child process {} status {}", reaped.pid, reaped.status);
        }

        retain_live_processes(&mut tracked_pids)?;
    }

    Ok(())
}

fn allow_one_notification(notification_fd: RawFd) -> anyhow::Result<libc::pid_t> {
    let request =
        ScmpNotifReq::receive(notification_fd).context("failed to receive seccomp notification")?;
    let pid = libc::pid_t::try_from(request.pid).context("notification pid out of range")?;

    let response = ScmpNotifResp::new_continue(request.id, ScmpNotifRespFlags::empty());
    response
        .respond(notification_fd)
        .context("failed to continue seccomp notification")?;

    Ok(pid)
}

fn retain_live_processes(tracked_pids: &mut HashSet<libc::pid_t>) -> anyhow::Result<()> {
    let mut dead = Vec::new();
    for &pid in tracked_pids.iter() {
        if !process::process_exists(pid)? {
            dead.push(pid);
        }
    }

    for pid in dead {
        tracked_pids.remove(&pid);
    }

    Ok(())
}

fn poll_fds(fds: &mut [libc::pollfd], timeout_ms: i32) -> anyhow::Result<()> {
    let nfds = libc::nfds_t::try_from(fds.len()).context("too many poll fds")?;

    loop {
        let result = {
            // SAFETY: fds points to a valid pollfd slice and nfds matches its length.
            unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) }
        };

        if result >= 0 {
            return Ok(());
        }

        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }

        bail!("poll failed: {error}");
    }
}
