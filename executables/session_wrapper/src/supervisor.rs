//! Seccomp user-notification supervisor loop for exec authorization.
//!
//! # Architecture overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  Parent (session-wrapper supervisor)                     │
//! │                                                          │
//! │  ┌────────────────┐     ┌──────────────┐                │
//! │  │ seccomp notif  │     │ TACACS+      │                │
//! │  │ fd (blocking)  │     │ agent (gRPC) │                │
//! │  └───────┬────────┘     └──────┬───────┘                │
//! │          │ recv_notification()  │ block_on(send_acct)    │
//! │          ▼                     │                         │
//! │  ┌───────────────────────────────────────────────────┐  │
//! │  │            run_supervisor() loop                  │  │
//! │  │                                                   │  │
//! │  │  1. poll(notif_fd, control_socket)               │  │
//! │  │  2. recv_notification() → ScmpNotifReq           │  │
//! │  │  3. read_exec_args() ← /proc/[pid]/mem           │  │
//! │  │  4. allowlist check  → CONTINUE (fast path)      │  │
//! │  │  5. IPC accounting   → allow or deny             │  │
//! │  │  6. send_response()                              │  │
//! │  └───────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────┐
//! │  Child / descendants (frozen at execve boundary)        │
//! │                                                          │
//! │  bash ──fork──► sub-bash ──fork──► script child ...     │
//! │   │               │                   │                  │
//! │   execve          execve              execve             │
//! │   (frozen)        (frozen)            (frozen)           │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Single-threaded blocking design
//!
//! The supervisor runs in the parent process's main thread and blocks on
//! `ScmpNotifReq::receive`.  No async runtime is needed for the notification
//! loop itself.  TACACS+ IPC calls (which are async) are driven via
//! `tokio::runtime::Runtime::block_on`, with a single-threaded tokio runtime
//! created once at supervisor startup and reused for the lifetime of the
//! session.
//!
//! # Descendant coverage
//!
//! The seccomp filter is inherited across `fork`/`clone` and preserved across
//! `exec`, so every process in the supervised tree — nested shells, subshells,
//! background jobs, shell scripts — hits the same notification fd.  The
//! supervisor loop stays alive until `waitpid` confirms that the process tree
//! is empty (the subreaper role ensures descendants are reparented to us, not
//! to PID 1, when their parent exits).
//!
//! # Fail policy
//!
//! When the TACACS+ agent is unreachable (network partition, service restart),
//! the supervisor applies the configured fail policy:
//!
//! | Policy             | Behaviour on IPC failure          |
//! |--------------------|-----------------------------------|
//! | [`FailPolicy::Closed`] | Deny the exec with `EPERM`    |
//! | [`FailPolicy::Open`]   | Allow the exec (continue)     |

use std::collections::HashSet;
use std::io;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use libseccomp::{ScmpFd, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags, notify_id_valid};
use tacacsrs_agent_client::{AccountingOperation, AccountingResponseStatus, IpcEndpoint, ServiceClient};
use tokio::runtime::Runtime;

use super::allowlist::Allowlist;
use super::cli::FailPolicy;
use super::process::{ChildSetupStatus, SessionProcess, reap_available_children, process_exists};
use super::process_reader::read_exec_args;

const SUPERVISOR_POLL_TIMEOUT_MS: i32 = 250;
const SUPERVISOR_IDLE_SLEEP: Duration = Duration::from_millis(250);

// ── low-level wrappers ───────────────────────────────────────────────────────

/// Blocks until the next seccomp user notification arrives on `notif_fd`.
///
/// This is a thin wrapper around [`ScmpNotifReq::receive`] that converts the
/// libseccomp error type to [`anyhow::Error`].  The call retries automatically
/// on `EINTR` (handled inside libseccomp-rs).
///
/// Returns the received notification request, which contains the PID of the
/// process that triggered the filter and the syscall arguments.
///
/// # When does this return an error?
///
/// When the notification fd is closed — which happens when all processes that
/// hold a copy of the seccomp filter have exited.  The supervisor loop treats
/// this as the session-termination signal.
pub(crate) fn recv_notification(notif_fd: ScmpFd) -> Result<ScmpNotifReq> {
    ScmpNotifReq::receive(notif_fd).context("failed to receive seccomp notification")
}

/// Sends a response to the kernel for a pending seccomp user notification.
///
/// The `resp.id` field must match the `id` from the corresponding
/// [`ScmpNotifReq`] or the kernel will return `ENOENT` (the notification is no
/// longer valid). Callers should always check [`check_notification_valid`]
/// before sending to handle the TOCTOU window gracefully.
pub(crate) fn send_response(notif_fd: ScmpFd, resp: ScmpNotifResp) -> Result<()> {
    resp.respond(notif_fd)
        .context("failed to send seccomp notification response")
}

/// Checks whether a seccomp user notification is still valid.
///
/// # Why this matters (TOCTOU)
///
/// Between the moment the supervisor receives a notification and the moment it
/// sends a response, the target process can be:
///
/// - Killed by a signal.
/// - Have the syscall cancelled by a signal (EINTR).
/// - Replaced entirely if the process is traced with ptrace.
///
/// Sending a response to an invalid notification returns `ENOENT`. Calling
/// this function between expensive operations (e.g. IPC round-trips) lets the
/// supervisor detect the race early and skip the response gracefully.
///
/// This does **not** eliminate the TOCTOU window — there is always a small
/// gap between the check and the subsequent operation.  It is a best-effort
/// mitigation, sufficient for an interactive shell use case.
///
/// # Errors
///
/// Returns an error if the notification is no longer valid (the target process
/// exited or the syscall was cancelled).
pub(crate) fn check_notification_valid(notif_fd: ScmpFd, id: u64) -> Result<()> {
    notify_id_valid(notif_fd, id).context("seccomp notification is no longer valid")
}

// ── IPC helpers ──────────────────────────────────────────────────────────────

/// Configuration passed from the CLI into the supervisor loop.
///
/// Collects all the context that comes from the operator-controlled CLI flags
/// so that the supervisor does not need to parse arguments itself.
#[derive(Debug)]
pub(crate) struct SupervisorConfig {
    /// TACACS+ username for the wrapped session.
    pub(crate) user: String,
    /// Optional port context for TACACS+ accounting records (e.g. `"ssh"`).
    pub(crate) port: Option<String>,
    /// Optional remote address for TACACS+ accounting records.
    pub(crate) rem_addr: Option<String>,
    /// What to do when the TACACS+ agent cannot be reached.
    pub(crate) fail_policy: FailPolicy,
    /// IPC endpoint of the local TACACS+ agent.
    pub(crate) service_endpoint: IpcEndpoint,
}

/// Outcome of an authorization decision for one exec notification.
#[derive(Debug)]
enum AuthDecision {
    /// Allow the exec to proceed (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
    Allow,
    /// Deny the exec; the process receives `EPERM`.
    Deny(String),
}

/// Attempts to connect to the TACACS+ agent and returns a usable client.
///
/// Returns `None` if the connection fails (the caller applies fail policy).
fn connect_ipc_client(rt: &Runtime, endpoint: &IpcEndpoint) -> Option<ServiceClient> {
    match rt.block_on(ServiceClient::connect(endpoint.clone())) {
        Ok(client) => {
            log::debug!("connected to TACACS+ agent at {endpoint:?}");
            Some(client)
        }
        Err(err) => {
            log::warn!("failed to connect to TACACS+ agent: {err:#}");
            None
        }
    }
}

/// Sends an accounting record to the TACACS+ agent and interprets the response
/// as an authorization decision.
///
/// # Mapping accounting status to allow/deny
///
/// TACACS+ accounting (`TAC_PLUS_ACCT`) is the available IPC operation in the
/// current implementation. The server's `status` field in the accounting reply
/// is used as a proxy for authorization:
///
/// | Status    | Decision |
/// |-----------|----------|
/// | `Success` | Allow    |
/// | `Error`   | Deny     |
/// | `Follow`  | Deny     |
///
/// A proper `TAC_PLUS_AUTHOR` authorization operation will replace this when
/// the command-authorization RPC is implemented in the agent.
///
/// # IPC failure
///
/// If the call fails (transport error, agent unavailable), `None` is returned
/// so the caller can apply the configured fail policy.
fn ipc_authorize(
    rt: &Runtime,
    client: &ServiceClient,
    config: &SupervisorConfig,
    exec_path: &str,
    exec_args: &[String],
) -> Option<AuthDecision> {
    let operation = AccountingOperation {
        user: config.user.clone(),
        port: config.port.clone().unwrap_or_default(),
        remote_address: config.rem_addr.clone().unwrap_or_default(),
        command: exec_path.to_owned(),
        command_arguments: exec_args.to_vec(),
    };

    match rt.block_on(client.send_accounting(operation)) {
        Ok(response) => {
            log::debug!(
                "IPC accounting for {exec_path:?}: status={:?} server={:?}",
                response.status,
                response.server
            );
            match response.status {
                AccountingResponseStatus::Success => Some(AuthDecision::Allow),
                AccountingResponseStatus::Error | AccountingResponseStatus::Follow => {
                    let reason =
                        format!("TACACS+ agent denied {exec_path:?}: status={:?}", response.status);
                    Some(AuthDecision::Deny(reason))
                }
            }
        }
        Err(err) => {
            log::warn!("IPC accounting call failed for {exec_path:?}: {err:#}");
            None // caller applies fail policy
        }
    }
}

/// Maps a fail policy to an [`AuthDecision`] for when IPC is unavailable.
fn fail_policy_decision(policy: FailPolicy, exec_path: &str) -> AuthDecision {
    match policy {
        FailPolicy::Open => {
            log::warn!("IPC unavailable, fail-open: allowing {exec_path:?}");
            AuthDecision::Allow
        }
        FailPolicy::Closed => {
            let reason = format!("IPC unavailable, fail-closed: denying {exec_path:?}");
            log::warn!("{reason}");
            AuthDecision::Deny(reason)
        }
    }
}

// ── notification handler ─────────────────────────────────────────────────────

/// Authorizes one exec notification and sends the kernel response.
///
/// # Steps
///
/// 1. Read the executable path and argv from the target process's memory.
/// 2. Check the allowlist — if matched, respond immediately with CONTINUE.
/// 3. Send a TACACS+ accounting record and interpret the response as
///    allow/deny. On IPC failure, apply the configured fail policy.
/// 4. Send the final response to the kernel.
///
/// # Notification invalidity
///
/// If the notification becomes invalid at any point (target process killed),
/// this function returns `Ok(())` after logging. The kernel has already
/// cleaned up the frozen syscall, so no response is needed.
fn handle_exec_notification(
    notif_fd: ScmpFd,
    req: &ScmpNotifReq,
    allowlist: &Allowlist,
    config: &SupervisorConfig,
    ipc_client: Option<&ServiceClient>,
    rt: &Runtime,
) -> Result<()> {
    let pid = req.pid;

    // Step 1: Read the executable path and argv from the target process.
    let exec_info = match read_exec_args(notif_fd, pid, req) {
        Ok(Some(info)) => info,
        Ok(None) => {
            // Non-exec syscall (fork/clone/etc.) — always continue.
            log::trace!("non-exec syscall from pid {pid}: allowing");
            let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
            // Ignore ENOENT here: if the notification is already invalid, there
            // is nothing to respond to.
            let _ = send_response(notif_fd, resp);
            return Ok(());
        }
        Err(err) => {
            // Reading failed — either the notification became invalid (process
            // was killed) or a genuine I/O error.  Check validity to distinguish.
            if check_notification_valid(notif_fd, req.id).is_err() {
                log::debug!(
                    "notification {id} from pid {pid} became invalid before memory read; skipping",
                    id = req.id
                );
                return Ok(());
            }
            // Some other I/O error — apply fail policy.
            log::warn!("failed to read exec args from pid {pid}: {err:#}");
            let decision = fail_policy_decision(config.fail_policy, "<unreadable>");
            return apply_decision(notif_fd, req, "<unreadable>", &decision);
        }
    };

    let (exec_path, exec_args) = exec_info;
    log::debug!("pid {pid} exec: {exec_path:?} args={exec_args:?}");

    // Step 2: Fast-path allowlist check.
    if allowlist.is_allowed(&exec_path) {
        log::debug!("allowlist hit for {exec_path:?}: allowing without IPC");
        let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
        let _ = send_response(notif_fd, resp);
        return Ok(());
    }

    // Step 3: IPC authorization.
    let decision = match ipc_client {
        Some(client) => {
            // Skip argv[0] in the arguments — it is conventionally a copy of
            // the executable name and redundant with exec_path.
            let args_without_argv0 = exec_args.get(1..).unwrap_or(&[]);
            match ipc_authorize(rt, client, config, &exec_path, args_without_argv0) {
                Some(decision) => decision,
                None => fail_policy_decision(config.fail_policy, &exec_path),
            }
        }
        None => {
            // IPC client was never established (agent unreachable at startup).
            fail_policy_decision(config.fail_policy, &exec_path)
        }
    };

    // Step 4: Send the kernel response.
    apply_decision(notif_fd, req, &exec_path, &decision)
}

/// Sends the allow or deny kernel response for a seccomp notification.
///
/// If sending fails because the notification has expired (the target process
/// exited during our IPC call), the function logs the race and returns `Ok(())`.
/// This is correct behaviour — there is no process left to deny or allow.
fn apply_decision(
    notif_fd: ScmpFd,
    req: &ScmpNotifReq,
    exec_path: &str,
    decision: &AuthDecision,
) -> Result<()> {
    match decision {
        AuthDecision::Allow => {
            log::debug!("allowing exec of {exec_path:?} for pid {}", req.pid);
            let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
            // `SECCOMP_USER_NOTIF_FLAG_CONTINUE` tells the kernel: proceed with
            // the original execve as if no filter existed.  This is the only
            // correct "allow" response for a user-notification filter — there is
            // no way to return a meaningful success value from execve otherwise.
            if let Err(err) = send_response(notif_fd, resp) {
                log_or_propagate_send_error(err, notif_fd, req.id)?;
            }
        }
        AuthDecision::Deny(ref reason) => {
            log::info!("denying exec of {exec_path:?} for pid {}: {reason}", req.pid);
            eprintln!("session-wrapper: exec denied: {exec_path}");
            // `-libc::EPERM` is the negative errno value the kernel will return
            // as the result of the blocked execve call.
            let resp = ScmpNotifResp::new_error(req.id, -libc::EPERM, ScmpNotifRespFlags::empty());
            if let Err(err) = send_response(notif_fd, resp) {
                log_or_propagate_send_error(err, notif_fd, req.id)?;
            }
        }
    }
    Ok(())
}

/// Handles an error from [`send_response`] by checking whether the notification
/// has expired in the meantime.
///
/// When the target process exits between our IPC call and our response, the
/// kernel discards the notification and `respond()` returns `ENOENT`. This is
/// an expected race — not an error the supervisor should propagate.
///
/// If the notification is still valid but `send_response` failed for some other
/// reason, the original error is returned.
fn log_or_propagate_send_error(err: anyhow::Error, notif_fd: ScmpFd, id: u64) -> Result<()> {
    if check_notification_valid(notif_fd, id).is_err() {
        // The notification expired: the target process already exited.
        // The respond() failure is therefore expected — nothing to do.
        log::debug!(
            "notification {id} expired before response could be sent;              ignoring respond error: {err:#}"
        );
        Ok(())
    } else {
        // Notification is still valid, so the send error is genuine.
        Err(err)
    }
}

// ── poll helpers ─────────────────────────────────────────────────────────────

/// Polls the provided file descriptors and returns when at least one has an
/// event (or the timeout expires).
///
/// Retries automatically on `EINTR` (e.g. from a signal handler).
fn poll_fds(fds: &mut [libc::pollfd], timeout_ms: i32) -> Result<()> {
    let nfds = libc::nfds_t::try_from(fds.len()).context("too many poll fds")?;

    loop {
        // SAFETY: fds points to a valid pollfd slice and nfds matches its length.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) };

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

/// Removes PIDs that no longer exist from the notification-observed PID set.
///
/// This is a secondary liveness cleanup on top of the subreaper `waitpid` loop.
/// The authoritative "any descendants still alive?" signal is the subreaper
/// state returned by `reap_available_children`; this function only prunes the
/// supplemental PID set used for debug logging.
fn retain_live_processes(tracked_pids: &mut HashSet<libc::pid_t>) -> Result<()> {
    let mut dead = Vec::new();
    for &pid in tracked_pids.iter() {
        if !process_exists(pid)? {
            dead.push(pid);
        }
    }
    for pid in dead {
        tracked_pids.remove(&pid);
    }
    Ok(())
}

// ── public supervisor loop ───────────────────────────────────────────────────

/// Runs the seccomp notification supervisor loop for the lifetime of a session.
///
/// # Overview
///
/// The supervisor:
///
/// 1. Creates a single-threaded tokio runtime for IPC accounting calls.
/// 2. Tries to connect to the TACACS+ agent (failure is not fatal — fail policy
///    governs what happens when the agent is unavailable).
/// 3. Releases the child process (signals the child that the supervisor is
///    ready to answer seccomp notifications).
/// 4. Enters a poll loop over the seccomp notification fd and the child setup
///    control socket.
/// 5. For each notification: reads exec args, checks the allowlist, optionally
///    calls the TACACS+ agent, and sends the kernel an allow or deny response.
/// 6. Exits when the subreaper has no more children (the entire process tree
///    spawned under the session has exited).
///
/// # Descendant notifications
///
/// Because the seccomp filter is inherited across `fork`/`clone` and preserved
/// across `exec`, every descendant of the initial shell — nested bash sessions,
/// subshells, background jobs, shell scripts — sends notifications through the
/// same `notif_fd`.  The supervisor does not track which PID triggered each
/// notification beyond logging; it authorizes each exec on its own merits.
///
/// The loop terminates based on the subreaper's child count, **not** on the
/// exit of the initial shell PID, so the notification fd stays alive until the
/// last descendant has exited.
///
/// # Arguments
///
/// * `session`   – Supervision handles for the child (PID, notification fd,
///   control socket).
/// * `allowlist` – Paths that bypass IPC and are always allowed.
/// * `config`    – Session context and fail policy.
pub(crate) fn run_supervisor(
    session: &SessionProcess,
    allowlist: &Allowlist,
    config: &SupervisorConfig,
) -> Result<()> {
    log::info!(
        "starting supervisor for child {} (fail-policy={:?})",
        session.child_pid(),
        config.fail_policy
    );

    // Create the tokio runtime used for IPC accounting calls. A single-thread
    // runtime is sufficient because we never issue concurrent RPCs.
    let rt = Runtime::new().context("failed to create tokio runtime for IPC")?;

    // Attempt to connect to the TACACS+ agent. Failure here is not fatal —
    // the fail policy determines what happens when IPC is unavailable.
    let ipc_client = connect_ipc_client(&rt, &config.service_endpoint);

    // Signal the child that the supervisor is ready to answer notifications.
    // The child has been waiting for this byte since installing the seccomp
    // filter. Without this signal, the child's first execve would block forever
    // with no supervisor to respond.
    session
        .signal_supervisor_ready()
        .context("failed to release child after supervisor setup")?;

    run_supervisor_loop(session, allowlist, config, &rt, ipc_client.as_ref())
}

/// State for one iteration of the supervisor poll loop.
struct LoopState {
    has_child_processes: bool,
    notification_fd_open: bool,
    control_socket_open: bool,
    tracked_pids: HashSet<libc::pid_t>,
}

/// Runs the supervisor event loop until the supervised process tree exits.
///
/// Extracted from [`run_supervisor`] so the outer function stays under the
/// clippy function-length limit while keeping the loop logic together.
fn run_supervisor_loop(
    session: &SessionProcess,
    allowlist: &Allowlist,
    config: &SupervisorConfig,
    rt: &Runtime,
    ipc_client: Option<&ServiceClient>,
) -> Result<()> {
    let mut state = LoopState {
        has_child_processes: true,
        notification_fd_open: true,
        control_socket_open: true,
        // `tracked_pids` records PIDs seen in notifications, but fork
        // notifications identify the caller, not the newly-created child.
        // The subreaper `waitpid` loop is the authoritative "any descendants
        // alive?" signal; this set is supplemental for debug logging.
        tracked_pids: HashSet::from([session.child_pid()]),
    };

    while state.has_child_processes || !state.tracked_pids.is_empty() {
        poll_loop_iteration(session, allowlist, config, rt, ipc_client, &mut state)?;
    }

    log::info!("supervisor exiting: all supervised processes have exited");
    Ok(())
}

/// Runs one iteration of the supervisor poll loop.
///
/// Polls the seccomp notification fd and the child control socket, dispatches
/// any pending events, and reaps exited children.
fn poll_loop_iteration(
    session: &SessionProcess,
    allowlist: &Allowlist,
    config: &SupervisorConfig,
    rt: &Runtime,
    ipc_client: Option<&ServiceClient>,
    state: &mut LoopState,
) -> Result<()> {
    let mut fds = build_poll_fds(session, state);

    if state.notification_fd_open || state.control_socket_open {
        poll_fds(&mut fds, SUPERVISOR_POLL_TIMEOUT_MS)?;
    } else {
        // Both fds are closed; sleep briefly to avoid a busy-wait while
        // waiting for the last descendant to exit.
        thread::sleep(SUPERVISOR_IDLE_SLEEP);
    }

    handle_control_socket_event(session, &fds, state)?;
    handle_notification_event(session, allowlist, config, rt, ipc_client, &fds, state)?;

    // ── Reap exited children ─────────────────────────────────────────────
    let reap_status = reap_available_children()?;
    state.has_child_processes = reap_status.has_children;
    for reaped in reap_status.reaped {
        state.tracked_pids.remove(&reaped.pid);
        log::debug!("reaped child process {} status {}", reaped.pid, reaped.status);
    }
    retain_live_processes(&mut state.tracked_pids)?;
    Ok(())
}

/// Builds the `pollfd` array for the current loop iteration.
///
/// Descriptors that are already closed are set to `-1` so `poll(2)` ignores
/// them without returning an error.
fn build_poll_fds(session: &SessionProcess, state: &LoopState) -> [libc::pollfd; 2] {
    [
        libc::pollfd {
            fd: if state.notification_fd_open {
                session.notification_fd()
            } else {
                -1
            },
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: if state.control_socket_open {
                session.control_socket_fd()
            } else {
                -1
            },
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        },
    ]
}

/// Processes any pending event on the child setup control socket.
fn handle_control_socket_event(
    session: &SessionProcess,
    fds: &[libc::pollfd; 2],
    state: &mut LoopState,
) -> Result<()> {
    if !state.control_socket_open
        || fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0
    {
        return Ok(());
    }
    match session
        .read_child_setup_status()
        .context("failed to read child setup status")?
    {
        ChildSetupStatus::ControlClosed => {
            state.control_socket_open = false;
            log::debug!(
                "child {} closed setup control socket at exec boundary",
                session.child_pid()
            );
        }
        ChildSetupStatus::Failed(message) => {
            bail!("child setup failed after supervisor ready: {message}");
        }
    }
    Ok(())
}

/// Processes any pending seccomp notification event.
fn handle_notification_event(
    session: &SessionProcess,
    allowlist: &Allowlist,
    config: &SupervisorConfig,
    rt: &Runtime,
    ipc_client: Option<&ServiceClient>,
    fds: &[libc::pollfd; 2],
    state: &mut LoopState,
) -> Result<()> {
    let events = fds[0].revents;
    if !state.notification_fd_open {
        return Ok(());
    }

    if events & (libc::POLLERR | libc::POLLNVAL) != 0 {
        bail!("seccomp notification fd reported unexpected poll events: {events:#x}");
    }

    if events & libc::POLLIN != 0 {
        match recv_notification(session.notification_fd()) {
            Ok(req) => {
                let pid = libc::pid_t::try_from(req.pid).unwrap_or_else(|_| session.child_pid());
                state.tracked_pids.insert(pid);
                log::trace!("notification from pid {pid}: syscall={:?}", req.data.syscall);
                handle_exec_notification(
                    session.notification_fd(),
                    &req,
                    allowlist,
                    config,
                    ipc_client,
                    rt,
                )
                .with_context(|| format!("failed to handle exec notification from pid {pid}"))?;
            }
            Err(err) => {
                // Error typically means the fd was closed concurrently.
                // The POLLHUP branch below will pick this up on the next poll.
                log::debug!("recv_notification error (likely fd closed): {err:#}");
            }
        }
    }

    if events & libc::POLLHUP != 0 {
        // All processes holding the seccomp filter have exited. No more
        // notifications will arrive. The supervisor keeps the loop alive
        // until the subreaper confirms all descendants have been reaped.
        state.notification_fd_open = false;
        log::debug!("seccomp notification fd closed (all supervised processes exited)");
    }

    Ok(())
}
