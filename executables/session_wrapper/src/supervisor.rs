//! Seccomp user-notification supervisor — async cooperative task design.
//!
//! # Why go async?
//!
//! The original design used a blocking poll loop with `block_on` for IPC calls.
//! While simple, it serialized notification handling: one exec had to complete
//! its TACACS+ round-trip before the next notification was even received. In a
//! busy shell session with many concurrent descendants (pipelines, background
//! jobs, nested scripts), this introduces unnecessary head-of-line blocking.
//!
//! The async design uses Tokio's cooperative scheduler to handle notifications
//! concurrently:
//!
//! - A dedicated OS thread runs the blocking `ScmpNotifReq::receive` loop and
//!   feeds notifications into a Tokio `mpsc` channel.  This decouples reception
//!   (inherently blocking, indefinite wait) from processing.
//! - Each notification spawns its own `tokio::task`.  While one task awaits a
//!   TACACS+ IPC response, other tasks can handle unrelated execs from sibling
//!   processes concurrently.
//! - Child reaping is driven by SIGCHLD plus a safety polling interval — no
//!   busy-wait, no fixed timeout penalty for each loop iteration.
//! - The control socket watcher runs in `spawn_blocking` (a short-lived
//!   blocking call) rather than in the poll loop, removing one manual fd from
//!   the poll array.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │  OS thread  (std::thread::spawn — long-lived blocker)               │
//! │                                                                       │
//! │  loop { ScmpNotifReq::receive(fd) }                                  │
//! │            │                                                          │
//! │            └──── mpsc::Sender<ScmpNotifReq> ───────────────────────► │
//! └──────────────────────────────────────────────────────────────────────┘
//!                                                                │
//!                                                       channel  │
//!                                                                ▼
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │  Tokio runtime  (multi-thread, 2 worker threads)                     │
//! │                                                                       │
//! │  dispatch_loop (main async task)                                     │
//! │  ┌───────────────────────────────────────────────────────────────┐   │
//! │  │  tokio::select! {                                             │   │
//! │  │    req = notif_rx.recv()  ──► tokio::spawn(handle_one(...))  │   │
//! │  │    _ = sigchld.recv()     ──► reap_available_children()      │   │
//! │  │    _ = reap_interval.tick() ► reap_available_children()      │   │
//! │  │    Some(_) = tasks.join_next() ──► (task completed)          │   │
//! │  │    result = &mut ctrl_rx  ──► propagate child setup error    │   │
//! │  │  }                                                            │   │
//! │  └───────────────────────────────────────────────────────────────┘   │
//! │                │                                                      │
//! │         spawn  │ per notification                                     │
//! │                ▼                                                      │
//! │  ┌─────────────────────────────────────────────────────────────┐     │
//! │  │  handle_one_notification  (concurrent Tokio tasks)          │     │
//! │  │                                                             │     │
//! │  │  read_exec_args()          ← /proc/[pid]/mem  (fast pread) │     │
//! │  │  allowlist.is_allowed()    ← HashSet O(1)                  │     │
//! │  │  client.send_authorization().await  ← async gRPC IPC       │     │
//! │  │  send_response()           ← kernel ioctl  (fast)          │     │
//! │  └─────────────────────────────────────────────────────────────┘     │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Concurrency safety of the notification fd
//!
//! The seccomp notification fd supports concurrent use from multiple threads:
//! `seccomp_notify_respond` uses the notification ID to route responses in the
//! kernel, so two tasks responding to different notifications simultaneously is
//! safe.  `seccomp_notify_receive` is only ever called from the single OS
//! receiver thread, so no locking is needed there.
//!
//! # Descendant coverage
//!
//! The seccomp filter is inherited across `fork`/`clone` and preserved across
//! `exec`.  Every process in the supervised tree — nested shells, subshells,
//! background jobs, shell scripts — sends notifications through the same fd.
//! The supervisor does not need to track which PID sent a notification; it
//! authorizes each exec on its own merits using the PID embedded in the request.
//!
//! # Fail policy
//!
//! | Policy             | Behaviour on IPC failure          |
//! |--------------------|-----------------------------------|
//! | [`FailPolicy::Closed`] | Deny the exec with `EPERM`    |
//! | [`FailPolicy::Open`]   | Allow the exec (continue)     |

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use libseccomp::{ScmpFd, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags, notify_id_valid};
use tacacsrs_agent_client::{
    AuthorizationArg, AuthorizationOperation, AuthorizationOperationResponse,
    AuthorizationResponseStatus, IpcEndpoint, ServiceClient,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::task::{JoinSet, spawn_blocking};
use tokio::time;

use super::allowlist::Allowlist;
use super::cli::FailPolicy;
use super::process::{
    ChildSetupStatus, SessionProcess, read_child_setup_status_fd, reap_available_children,
};
use super::process_reader::read_exec_args;

/// How often the dispatch loop polls for reaped children in addition to SIGCHLD.
///
/// This safety interval catches any SIGCHLD signals that were coalesced or
/// delivered while the process was not yet awaiting the signal.
const CHILD_REAP_INTERVAL: Duration = Duration::from_millis(250);

// ── low-level wrappers ───────────────────────────────────────────────────────

/// Blocks until the next seccomp user notification arrives on `notif_fd`.
///
/// This is a thin wrapper around [`ScmpNotifReq::receive`] that converts the
/// libseccomp error type to [`anyhow::Error`]. It retries automatically on
/// `EINTR` (handled inside libseccomp-rs).
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
/// - Have the syscall cancelled by a signal (`EINTR`).
/// - Replaced entirely if the process is traced with `ptrace`.
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

// ── configuration ─────────────────────────────────────────────────────────────

/// Configuration passed from the CLI into the supervisor.
///
/// Collects all operator-controlled CLI flags so the supervisor does not need
/// to parse arguments itself. Wrapped in `Arc` so it can be cheaply shared
/// across concurrent notification-handler tasks.
#[derive(Debug)]
pub(crate) struct SupervisorConfig {
    /// TACACS+ username for the wrapped session.
    pub(crate) user: String,
    /// Optional port context for TACACS+ authorization requests (e.g. `"ssh"`).
    pub(crate) port: Option<String>,
    /// Optional remote address for TACACS+ authorization requests.
    pub(crate) rem_addr: Option<String>,
    /// What to do when the TACACS+ agent cannot be reached.
    pub(crate) fail_policy: FailPolicy,
    /// IPC endpoint of the local TACACS+ agent.
    pub(crate) service_endpoint: IpcEndpoint,
    /// Maximum time to wait for one authorization IPC reply before applying fail policy.
    pub(crate) authorization_timeout: Duration,
    /// Current TACACS+ privilege level for this wrapped user.
    pub(crate) privilege_level: u32,
}

// ── authorization primitives ─────────────────────────────────────────────────

/// Outcome of an authorization decision for one exec notification.
#[derive(Debug)]
enum AuthDecision {
    /// Allow the exec to proceed (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
    Allow,
    /// Deny the exec; the process receives `EPERM`.
    Deny(String),
}

/// Connects to the TACACS+ agent and returns a usable client.
///
/// Returns `None` if the connection fails; the caller applies the fail policy.
async fn connect_ipc_client(endpoint: &IpcEndpoint) -> Option<ServiceClient> {
    match ServiceClient::connect(endpoint.clone()).await {
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

/// Sends an authorization request and maps the reply to an allow/deny decision.
///
/// # Mapping authorization status → allow/deny
///
/// | Status      | Decision |
/// |-------------|----------|
/// | `PassAdd`   | Allow if no mandatory response args must be applied |
/// | `PassRepl`  | Allow if no mandatory replacement args must be applied |
/// | `Fail`      | Deny     |
/// | `Error`     | Deny     |
/// | `Follow`    | Deny     |
///
/// Returns `None` if the IPC call fails so the caller can apply the fail policy.
async fn ipc_authorize(
    client: &ServiceClient,
    config: &SupervisorConfig,
    exec_path: &str,
    exec_args: &[String],
) -> Option<AuthDecision> {
    let mut builder = AuthorizationOperation::builder(config.user.clone(), config.privilege_level)
        .port(config.port.clone().unwrap_or_default())
        .remote_address(config.rem_addr.clone().unwrap_or_default())
        .service("shell")
        .command(exec_path.to_owned())
        .command_args(exec_args.iter().cloned());
    let operation = match builder.build() {
        Ok(operation) => operation,
        Err(err) => {
            log::warn!("failed to build IPC authorization request for {exec_path:?}: {err:#}");
            return None;
        }
    };

    match time::timeout(config.authorization_timeout, client.send_authorization(operation)).await {
        Err(_) => {
            log::warn!("IPC authorization call timed out for {exec_path:?}");
            None
        }
        Ok(Err(err)) => {
            log::warn!("IPC authorization call failed for {exec_path:?}: {err:#}");
            None
        }
        Ok(Ok(response)) => {
            log::debug!(
                "IPC authorization for {exec_path:?}: status={:?} server={:?}",
                response.status,
                response.server
            );
            Some(map_authorization_response(&response, exec_path))
        }
    }
}

/// Maps an authorization response into the local seccomp decision.
///
/// Seccomp user notification can either continue the original frozen `execve`
/// or deny it; it cannot inject additional argv values or replace the submitted
/// argv. RFC 8907 lets clients ignore optional response args, but mandatory
/// response args must be applied or authorization fails.
fn map_authorization_response(
    response: &AuthorizationOperationResponse,
    exec_path: &str,
) -> AuthDecision {
    match response.status {
        AuthorizationResponseStatus::PassAdd => {
            map_pass_with_args("PASS_ADD", "response", response.args.as_slice(), exec_path)
        }
        AuthorizationResponseStatus::PassRepl => {
            map_pass_with_args("PASS_REPL", "replacement", response.args.as_slice(), exec_path)
        }
        AuthorizationResponseStatus::Fail
        | AuthorizationResponseStatus::Error
        | AuthorizationResponseStatus::Follow => {
            let reason =
                format!("TACACS+ agent denied {exec_path:?}: status={:?}", response.status);
            AuthDecision::Deny(reason)
        }
    }
}

fn map_pass_with_args(
    status_name: &str,
    arg_kind: &str,
    args: &[AuthorizationArg],
    exec_path: &str,
) -> AuthDecision {
    if args.is_empty() {
        return AuthDecision::Allow;
    }

    let arg_names: Vec<&str> = args.iter().map(|a| a.name.as_str()).collect();
    let mandatory_names: Vec<&str> = args
        .iter()
        .filter(|a| a.mandatory)
        .map(|a| a.name.as_str())
        .collect();

    if mandatory_names.is_empty() {
        log::warn!(
            "IPC authorization {status_name} for {exec_path:?} returned optional {arg_kind} \
             args {arg_names:?} that cannot be applied in seccomp notify mode; ignoring them"
        );
        AuthDecision::Allow
    } else {
        log::warn!(
            "IPC authorization {status_name} for {exec_path:?} returned mandatory {arg_kind} \
             args {mandatory_names:?} (all args: {arg_names:?}) that cannot be applied in seccomp \
             notify mode; treating as failed per RFC 8907 §6.2"
        );
        AuthDecision::Deny(format!(
            "TACACS+ agent returned {status_name} for {exec_path:?} with mandatory {arg_kind} \
             arg(s) that cannot be applied: {mandatory_names:?}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization_response(
        status: AuthorizationResponseStatus,
        args: Vec<AuthorizationArg>,
    ) -> AuthorizationOperationResponse {
        AuthorizationOperationResponse {
            server: "test-server".to_owned(),
            status,
            server_message: String::new(),
            args,
            data: String::new(),
        }
    }

    #[test]
    fn pass_add_with_only_optional_response_args_is_allowed() {
        let response = authorization_response(
            AuthorizationResponseStatus::PassAdd,
            vec![AuthorizationArg::optional("priv-lvl", "15")],
        );

        let decision = map_authorization_response(&response, "/bin/echo");

        assert!(matches!(decision, AuthDecision::Allow));
    }

    #[test]
    fn pass_repl_with_only_optional_replacement_args_is_allowed() {
        let response = authorization_response(
            AuthorizationResponseStatus::PassRepl,
            vec![AuthorizationArg::optional("cmd-arg", "ignored")],
        );

        let decision = map_authorization_response(&response, "/bin/echo");

        assert!(matches!(decision, AuthDecision::Allow));
    }

    #[test]
    fn pass_add_with_mandatory_response_arg_is_denied() {
        let response = authorization_response(
            AuthorizationResponseStatus::PassAdd,
            vec![AuthorizationArg::mandatory("priv-lvl", "15")],
        );

        let decision = map_authorization_response(&response, "/bin/echo");

        match decision {
            AuthDecision::Deny(reason) => assert!(reason.contains("priv-lvl")),
            AuthDecision::Allow => panic!("mandatory PASS_ADD response arg was allowed"),
        }
    }

    #[test]
    fn pass_repl_with_mandatory_replacement_arg_is_denied() {
        let response = authorization_response(
            AuthorizationResponseStatus::PassRepl,
            vec![AuthorizationArg::mandatory("cmd", "/bin/date")],
        );

        let decision = map_authorization_response(&response, "/bin/echo");

        match decision {
            AuthDecision::Deny(reason) => assert!(reason.contains("cmd")),
            AuthDecision::Allow => panic!("mandatory PASS_REPL replacement arg was allowed"),
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

// ── per-notification handler ─────────────────────────────────────────────────

/// Authorizes one exec notification and sends the kernel response.
///
/// This function runs as an independent Tokio task so that concurrent execs
/// from different descendant processes are authorized in parallel — one task's
/// TACACS+ round-trip does not block another task from starting.
///
/// # Steps
///
/// 1. Read the executable path and argv from the target process's memory.
/// 2. Check the allowlist — if matched, respond immediately with CONTINUE.
/// 3. Send a TACACS+ authorization request (`await`) and interpret the response.
/// 4. Send the kernel the allow or deny response.
///
/// # Notification invalidity
///
/// If the notification becomes invalid (target process killed) at any step,
/// this function returns `Ok(())` after logging — the kernel has already
/// cleaned up the frozen syscall, so no response is needed.
async fn handle_one_notification(
    notif_fd: ScmpFd,
    req: ScmpNotifReq,
    allowlist: Arc<Allowlist>,
    config: Arc<SupervisorConfig>,
    client: Option<Arc<ServiceClient>>,
) -> Result<()> {
    let pid = req.pid;

    // Step 1: Read exec path and argv from /proc/[pid]/mem.
    //
    // `read_exec_args` uses pread(2) on /proc/[pid]/mem.  Each individual
    // pread is bounded (max 4096 bytes, max 256 argv entries) and typically
    // completes in microseconds — fast enough to run synchronously in an async
    // task without spawn_blocking.
    let exec_info = match read_exec_args(notif_fd, pid, &req) {
        Ok(Some(info)) => info,
        Ok(None) => {
            // Non-exec syscall (fork/clone/etc.) — always continue.
            log::trace!("non-exec syscall from pid {pid}: allowing");
            let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
            if let Err(err) = send_response(notif_fd, resp) {
                log_or_propagate_send_error(err, notif_fd, req.id)?;
            }
            return Ok(());
        }
        Err(err) => {
            if check_notification_valid(notif_fd, req.id).is_err() {
                log::debug!(
                    "notification {id} from pid {pid} became invalid before memory read; skipping",
                    id = req.id
                );
                return Ok(());
            }
            log::warn!("failed to read exec args from pid {pid}: {err:#}");
            let decision = fail_policy_decision(config.fail_policy, "<unreadable>");
            return apply_decision(notif_fd, &req, "<unreadable>", &decision);
        }
    };

    let (exec_path, exec_args) = exec_info;
    log::debug!("pid {pid} exec: {exec_path:?} args={exec_args:?}");

    // Step 2: Fast-path allowlist check (O(1) HashSet lookup).
    if allowlist.is_allowed(&exec_path) {
        log::debug!("allowlist hit for {exec_path:?}: allowing without IPC");
        let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
        if let Err(err) = send_response(notif_fd, resp) {
            log_or_propagate_send_error(err, notif_fd, req.id)?;
        }
        return Ok(());
    }

    // Step 3: IPC authorization (async — this is where concurrency pays off).
    let decision = match client.as_deref() {
        Some(c) => {
            // Skip argv[0] — it is conventionally a copy of the executable
            // name and redundant with exec_path.
            let args_without_argv0 = exec_args.get(1..).unwrap_or(&[]);
            match ipc_authorize(c, &config, &exec_path, args_without_argv0).await {
                Some(decision) => decision,
                None => fail_policy_decision(config.fail_policy, &exec_path),
            }
        }
        None => fail_policy_decision(config.fail_policy, &exec_path),
    };

    // Step 4: Respond to the kernel.
    apply_decision(notif_fd, &req, &exec_path, &decision)
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
            // `SECCOMP_USER_NOTIF_FLAG_CONTINUE` tells the kernel to proceed with
            // the original execve as if no filter existed — the only correct
            // "allow" response for a user-notification filter.
            if let Err(err) = send_response(notif_fd, resp) {
                log_or_propagate_send_error(err, notif_fd, req.id)?;
            }
        }
        AuthDecision::Deny(ref reason) => {
            log::info!("denying exec of {exec_path:?} for pid {}: {reason}", req.pid);
            eprintln!("session-wrapper: exec denied: {exec_path}");
            // `-libc::EPERM` is the negative errno returned to the blocked execve.
            let resp = ScmpNotifResp::new_error(req.id, -libc::EPERM, ScmpNotifRespFlags::empty());
            if let Err(err) = send_response(notif_fd, resp) {
                log_or_propagate_send_error(err, notif_fd, req.id)?;
            }
        }
    }
    Ok(())
}

/// Handles a `send_response` error by re-checking notification validity.
///
/// When the target process exits between our IPC call and our `respond()` call,
/// the kernel discards the notification and returns `ENOENT`. This is an
/// expected race — not an error the supervisor should propagate.
fn log_or_propagate_send_error(err: anyhow::Error, notif_fd: ScmpFd, id: u64) -> Result<()> {
    if check_notification_valid(notif_fd, id).is_err() {
        log::debug!(
            "notification {id} expired before response could be sent; ignoring respond error: {err:#}"
        );
        Ok(())
    } else {
        Err(err)
    }
}

// ── notification receiver thread ─────────────────────────────────────────────

/// Runs the blocking `ScmpNotifReq::receive` loop in a dedicated OS thread.
///
/// # Why a dedicated OS thread?
///
/// `ScmpNotifReq::receive` is a blocking syscall that can wait indefinitely
/// for the next notification.  Tokio tasks must not block their worker threads
/// for long periods; `spawn_blocking` is intended for short-lived blocking
/// work.  A dedicated `std::thread` is the right tool for a long-running
/// blocking loop that feeds a channel.
///
/// When the notification fd is closed (all supervised processes exited), the
/// receive call returns an error and this function exits, dropping the sender.
/// The `mpsc::Receiver` on the tokio side sees the channel close and knows
/// no more notifications will arrive.
// The sender must be owned (not borrowed) so it is dropped when this function
// exits, signalling the channel receiver that no more notifications are coming.
// Clippy flags this as "needless pass by value" because `blocking_send` takes
// `&self`, but ownership here is intentional for the drop signal.
#[allow(clippy::needless_pass_by_value)]
fn notification_receiver(notif_fd: ScmpFd, tx: mpsc::Sender<ScmpNotifReq>) {
    loop {
        match recv_notification(notif_fd) {
            Ok(req) => {
                if tx.blocking_send(req).is_err() {
                    // Channel closed: supervisor is shutting down.
                    break;
                }
            }
            Err(err) => {
                log::debug!("notification receiver exiting (fd closed or error): {err:#}");
                break;
            }
        }
    }
}

// ── control socket watcher ───────────────────────────────────────────────────

/// Reads child setup status frames from the control socket until it closes.
///
/// Runs in `tokio::task::spawn_blocking` so it does not occupy a Tokio worker
/// thread while blocking.  The control socket closes when the child reaches
/// `execv` (success path) or when the child sends an error frame (failure path).
///
/// Returns `Ok(())` on the success path (`ControlClosed`), or an error if the
/// child reported a setup failure.
fn watch_control_socket(control_fd: ScmpFd) -> Result<()> {
    // The control socket protocol is single-shot after the ready signal:
    // the child either closes the socket (exec boundary = success) or sends
    // an error frame (setup failure). No multi-message loop is needed.
    match read_child_setup_status_fd(control_fd).context("failed to read child setup status")? {
        ChildSetupStatus::ControlClosed => {
            log::debug!("child setup control socket closed (exec boundary reached)");
            Ok(())
        }
        ChildSetupStatus::Failed(message) => {
            bail!("child setup failed after supervisor ready: {message}")
        }
    }
}

// ── child reaping ─────────────────────────────────────────────────────────────

/// Reaps all currently exited children and returns whether any remain.
///
/// Logs each reaped PID at debug level. Uses `waitpid(-1, WNOHANG)` internally
/// so this function is non-blocking and safe to call from an async context.
fn reap_children() -> Result<bool> {
    let status = reap_available_children()?;
    for reaped in &status.reaped {
        log::debug!("reaped child process {} status {}", reaped.pid, reaped.status);
    }
    Ok(status.has_children)
}

// ── public supervisor entry point ────────────────────────────────────────────

/// Runs the seccomp notification supervisor for the lifetime of a session.
///
/// # Overview
///
/// 1. Connects to the TACACS+ agent (failure is non-fatal; fail policy applies).
/// 2. Signals the child that the supervisor is ready to answer notifications.
/// 3. Spawns a dedicated OS thread to run the blocking receive loop.
/// 4. Registers a SIGCHLD handler for child reaping.
/// 5. Starts the control socket watcher in `spawn_blocking`.
/// 6. Runs the async dispatch loop until all supervised processes have exited.
///
/// # Arguments
///
/// * `session`   – Parent-side supervision handles (PID, fds, control socket).
/// * `allowlist` – Paths that bypass IPC and are always allowed.
/// * `config`    – Session context (user, port, fail policy) and IPC endpoint.
pub(crate) async fn run_supervisor(
    session: &SessionProcess,
    allowlist: Arc<Allowlist>,
    config: Arc<SupervisorConfig>,
) -> Result<()> {
    log::info!(
        "starting supervisor for child {} (fail-policy={:?})",
        session.child_pid(),
        config.fail_policy,
    );

    // Connect to the TACACS+ agent.  Failure is non-fatal: the fail policy
    // determines what happens for each notification when IPC is unavailable.
    let client = connect_ipc_client(&config.service_endpoint)
        .await
        .map(Arc::new);

    // Register the SIGCHLD handler before releasing the child.  A child that
    // exits immediately after being released would be missed if we registered
    // the handler after signal_supervisor_ready().
    let sigchld = signal(SignalKind::child()).context("failed to register SIGCHLD handler")?;

    // Signal the child that the supervisor is ready to answer notifications.
    // The child has been waiting for this byte since installing the seccomp
    // filter.  Without this signal, the child's first execve would block
    // forever with no supervisor to respond.
    session
        .signal_supervisor_ready()
        .context("failed to release child after supervisor setup")?;

    // Channel from the dedicated receiver thread to the dispatch loop.
    // Buffer capacity of 64 lets the receiver outpace the dispatcher during
    // a brief burst without blocking the receiver thread.
    let (notif_tx, notif_rx) = mpsc::channel::<ScmpNotifReq>(64);

    let notif_fd = session.notification_fd();

    // Spawn the blocking notification receive loop in a dedicated OS thread.
    // `std::thread::spawn` is appropriate here because this is a long-lived
    // blocking loop, not a short-lived blocking operation (which would use
    // spawn_blocking).
    std::thread::Builder::new()
        .name("notif-receiver".to_owned())
        .spawn(move || notification_receiver(notif_fd, notif_tx))
        .context("failed to spawn notification receiver thread")?;

    // Control socket watcher: runs in spawn_blocking because read(2) on the
    // control socket is briefly blocking (waits for the child to exec or fail).
    let control_fd = session.control_socket_fd();
    let ctrl_handle = spawn_blocking(move || watch_control_socket(control_fd));

    dispatch_loop(notif_fd, notif_rx, allowlist, config, client, sigchld, ctrl_handle).await
}

// ── dispatch loop ─────────────────────────────────────────────────────────────

/// Drives the async dispatch loop until the supervised process tree exits.
///
/// The loop runs four concurrent logical streams via `tokio::select!`:
///
/// 1. **Notifications** — received from the OS-thread channel; each spawns a
///    handler task.
/// 2. **SIGCHLD** — triggers a `waitpid(WNOHANG)` reap pass.
/// 3. **Reap interval** — a 250 ms safety net for coalesced or missed SIGCHLDs.
/// 4. **Control socket** — propagates a child setup failure as an error.
///
/// The loop exits when:
/// - The notification receiver thread exits (channel closed).
/// - All spawned handler tasks have completed.
/// - `waitpid` reports no remaining children (`ECHILD`).
///
/// Extracted from [`run_supervisor`] to keep function sizes within clippy
/// limits while keeping the full control flow visible in one place.
async fn dispatch_loop(
    notif_fd: ScmpFd,
    mut notif_rx: mpsc::Receiver<ScmpNotifReq>,
    allowlist: Arc<Allowlist>,
    config: Arc<SupervisorConfig>,
    client: Option<Arc<ServiceClient>>,
    mut sigchld: tokio::signal::unix::Signal,
    mut ctrl_handle: tokio::task::JoinHandle<Result<()>>,
) -> Result<()> {
    let mut handler_tasks: JoinSet<()> = JoinSet::new();
    let mut notifications_open = true;
    let mut has_children = true;
    let mut ctrl_done = false;

    // Safety-net reap interval: catches any SIGCHLD that was coalesced or
    // delivered before the signal handler was registered.
    let mut reap_interval = time::interval(CHILD_REAP_INTERVAL);
    reap_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // ── Incoming notification ───────────────────────────────────────
            req = notif_rx.recv(), if notifications_open => {
                if let Some(req) = req {
                    let pid = req.pid;
                    let al = allowlist.clone();
                    let cfg = config.clone();
                    let cl = client.clone();
                    handler_tasks.spawn(async move {
                        if let Err(e) =
                            handle_one_notification(notif_fd, req, al, cfg, cl).await
                        {
                            log::warn!("notification handler for pid {pid} failed: {e:#}");
                        }
                    });
                } else {
                    // Receiver thread exited: notification fd is closed.
                    // All processes holding the filter have exited.
                    notifications_open = false;
                    log::debug!(
                        "notification receiver channel closed \
                         (all supervised processes exited)"
                    );
                }
            }

            // ── SIGCHLD: a child or descendant exited ───────────────────────
            _ = sigchld.recv() => {
                has_children = reap_children()
                    .context("failed to reap children on SIGCHLD")?;
            }

            // ── Periodic safety reap ────────────────────────────────────────
            _ = reap_interval.tick() => {
                has_children = reap_children()
                    .context("failed to reap children in periodic reap")?;
            }

            // ── Handler task completed ──────────────────────────────────────
            Some(result) = handler_tasks.join_next() => {
                if let Err(e) = result {
                    log::warn!("notification handler task panicked: {e}");
                }
            }

            // ── Control socket: child setup status ──────────────────────────
            res = &mut ctrl_handle, if !ctrl_done => {
                ctrl_done = true;
                match res {
                    Ok(Ok(())) => {} // ControlClosed: child exec'd the shell
                    Ok(Err(e)) => return Err(e),
                    Err(e) => bail!("control socket watcher task panicked: {e}"),
                }
            }
        }

        // Exit when: no more notifications will arrive, all in-flight handlers
        // have finished, and all child processes have been reaped.
        if !notifications_open && handler_tasks.is_empty() && !has_children {
            break;
        }
    }

    log::info!("supervisor exiting: all supervised processes have exited");
    Ok(())
}
