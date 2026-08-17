//! Fork/exec lifecycle support for the Linux session wrapper.
//!
//! The important hand-off is:
//!
//! 1. The parent creates a pair of connected Unix domain sockets, then calls `fork`.
//! 2. The child installs the seccomp user-notification filter in its own
//!    process, sends the resulting notification fd to the parent with
//!    `SCM_RIGHTS`, and then waits for a one-byte "supervisor ready" signal.
//! 3. The parent owns the notification fd, starts the supervisor path, and only
//!    then releases the child.
//! 4. The child drops privileges and `execv`s the requested command.
//!
//! This is deliberately not implemented with `std::process::Command`: the
//! parent must receive the seccomp listener before the child is allowed to run
//! `execve`. If the child calls `execve` before the listener exists, the call
//! blocks forever because no supervisor can answer it.
//! The control socket also gives the child a way to report setup failures after
//! fork, where returning a normal Rust error to the parent is no longer
//! possible.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

use anyhow::{bail, Context, Result};

use super::seccomp;

const READY_BYTE: u8 = b'R';
const FD_MESSAGE: u8 = b'F';
const ERROR_MESSAGE: u8 = b'E';
const MAX_CHILD_ERROR_LEN: u32 = 64 * 1024;

/// Configuration copied into the forked child before it drops privileges.
///
/// These values are intentionally plain owned data so the child branch does not
/// need to borrow parent state after `fork()`.
#[derive(Debug, Clone)]
pub(crate) struct ChildProcessConfig {
    pub(crate) command: Vec<String>,
    pub(crate) user: String,
    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::gid_t,
}

/// Owns the parent-side handles for a supervised child session.
///
/// Keeping this value alive keeps both the seccomp listener and the control
/// socket alive. Dropping it is therefore a meaningful lifecycle event: the
/// wrapper can no longer answer seccomp notifications for the child tree.
#[derive(Debug)]
pub(crate) struct SessionProcess {
    child_pid: libc::pid_t,
    child_process_group_id: libc::pid_t,
    child_session_id: libc::pid_t,
    notification_fd: OwnedFd,
    control_socket: OwnedFd,
}

/// Messages the child can send after the parent releases it.
///
/// A clean `execv` closes the child's `SOCK_CLOEXEC` control socket, which the
/// parent treats as the exec boundary. Failures before exec are sent as an
/// explicit error frame so the top-level wrapper can fail loudly instead of
/// hanging or reporting a generic child exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChildSetupStatus {
    ControlClosed,
    Failed(String),
}

/// One child or subreaped descendant collected by `waitpid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReapedProcess {
    pub(crate) pid: libc::pid_t,
    pub(crate) status: i32,
}

/// Result of a non-blocking reap pass.
///
/// Without `has_children`, a plain `Vec<ReapedProcess>` loses this information:
/// `waitpid(..., WNOHANG)` returning 0 means at least one child or subreaped
/// descendant still exists even if none exited during this pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReapStatus {
    pub(crate) reaped: Vec<ReapedProcess>,
    pub(crate) has_children: bool,
}

impl SessionProcess {
    /// Returns the PID of the initially forked child process.
    pub(crate) fn child_pid(&self) -> libc::pid_t {
        self.child_pid
    }

    /// Returns the process group ID observed immediately after fork.
    pub(crate) fn child_process_group_id(&self) -> libc::pid_t {
        self.child_process_group_id
    }

    /// Returns the session ID observed immediately after fork.
    pub(crate) fn child_session_id(&self) -> libc::pid_t {
        self.child_session_id
    }

    /// Returns the parent-owned seccomp user notification listener fd.
    ///
    /// This fd is consumed by the supervisor loop. The child closes its own copy
    /// before it is released, so this descriptor is the authoritative listener.
    pub(crate) fn notification_fd(&self) -> RawFd {
        self.notification_fd.as_raw_fd()
    }

    /// Returns the parent side of the child setup control socket.
    pub(crate) fn control_socket_fd(&self) -> RawFd {
        self.control_socket.as_raw_fd()
    }

    /// Releases the child after the parent starts its supervisor path.
    ///
    /// The child blocks on this byte after installing seccomp and sending the
    /// notification fd. This prevents the child's first `execve` from being
    /// notified before the parent is ready to respond.
    pub(crate) fn signal_supervisor_ready(&self) -> Result<()> {
        write_all(self.control_socket.as_raw_fd(), &[READY_BYTE])
            .context("failed to signal child that supervisor is ready")
    }
}

/// Forks the wrapped session process and returns the parent-side supervision handles.
///
/// The returned session is not released yet. Callers must start whatever will
/// answer seccomp notifications, then call `signal_supervisor_ready` before the
/// child can drop privileges and exec the requested command.
pub(crate) fn spawn_session(config: ChildProcessConfig) -> Result<SessionProcess> {
    // Descendants that outlive the initial command are reparented to this process
    // instead of PID 1. That gives the supervisor a reliable way to keep the
    // notification fd alive until the whole wrapped process tree is gone.
    enable_child_subreaper().context("failed to mark session-wrapper as child subreaper")?;

    let (parent_socket, child_socket) =
        socket_pair().context("failed to create control socketpair")?;

    let fork_result = {
        // SAFETY: fork has no Rust wrapper. This call happens before any threads
        // are started by session-wrapper. Both branches immediately close the
        // unused socket end and avoid sharing borrowed stack references.
        unsafe { libc::fork() }
    };

    match fork_result {
        -1 => bail!("failed to fork session process: {}", io::Error::last_os_error()),
        0 => {
            drop(parent_socket);
            run_child_or_exit(child_socket, config);
        }
        child_pid => {
            drop(child_socket);
            // This blocks until the child installs seccomp and transfers
            // the listener fd, or until it reports a setup error. The parent
            // must not signal readiness before this point. Otherwise, the child
            // can reach a notified syscall with no listener running.
            let notification_fd =
                recv_initial_child_message(parent_socket.as_raw_fd(), Some(child_pid))
                    .context("failed to receive seccomp notification fd from child")?;
            let child_process_group_id =
                process_group_id(child_pid).context("failed to read child process group id")?;
            let child_session_id =
                session_id(child_pid).context("failed to read child session id")?;

            Ok(SessionProcess {
                child_pid,
                child_process_group_id,
                child_session_id,
                notification_fd,
                control_socket: parent_socket,
            })
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
/// Runs child setup and exits without unwinding back into the forked process.
///
/// This function never returns. The child branch must avoid running parent-side
/// destructors after fork, so it reports any setup error over the control socket
/// and then calls `_exit`.
fn run_child_or_exit(control_socket: OwnedFd, config: ChildProcessConfig) -> ! {
    if let Err(error) = run_child(&control_socket, &config) {
        if let Err(send_error) = send_child_error(control_socket.as_raw_fd(), &format!("{error:?}"))
        {
            eprintln!("session-wrapper child failed to report setup error: {send_error:?}");
        }
        eprintln!("session-wrapper child error: {error:?}");
    }

    // SAFETY: exit the forked child without running parent-process destructors.
    unsafe { libc::_exit(1) }
}

/// Performs the child-side setup sequence before replacing the process image.
///
/// Setup order is security-critical: install seccomp first, transfer the
/// listener fd, wait for parent readiness, drop privileges, then exec the command.
fn run_child(control_socket: &OwnedFd, config: &ChildProcessConfig) -> Result<()> {
    // Install the filter before the code drops privileges or runs `exec` on the
    // command. This mediates the entire user session, including the first exec.
    let notification_fd = seccomp::install_filter()
        .context("failed to install session-wrapper seccomp filter in child")?;
    send_fd(control_socket.as_raw_fd(), notification_fd)
        .context("failed to send seccomp notification fd to parent")?;
    // After the SCM_RIGHTS transfer, the child must not keep its copy open. The
    // parent's `OwnedFd` must control the supervisor's lifetime. No listener fd
    // must leak into the user command.
    close_fd(notification_fd).context("failed to close child copy of seccomp notification fd")?;

    // The ready byte is the synchronization point that proves the parent has a
    // notification loop ready to continue the child's first exec.
    wait_for_ready(control_socket.as_raw_fd())
        .context("failed to receive supervisor ready byte")?;
    drop_privileges(&config.user, config.gid, config.uid).with_context(|| {
        format!(
            "failed to drop privileges to user {} (uid {}, gid {})",
            config.user, config.uid, config.gid
        )
    })?;

    exec_command(&config.command)
}

/// Creates the bidirectional control socket used across fork.
///
/// The socket is close-on-exec so the parent can distinguish successful exec
/// from setup failure: successful exec closes the child end automatically.
fn socket_pair() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    let result = {
        // SAFETY: socketpair initializes both entries in fds on success.
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        }
    };

    if result == -1 {
        bail!("socketpair failed: {}", io::Error::last_os_error());
    }

    let parent = {
        // SAFETY: socketpair returned a valid owned fd at fds[0].
        unsafe { OwnedFd::from_raw_fd(fds[0]) }
    };
    let child = {
        // SAFETY: socketpair returned a valid owned fd at fds[1].
        unsafe { OwnedFd::from_raw_fd(fds[1]) }
    };

    Ok((parent, child))
}

#[allow(clippy::cast_ptr_alignment)]
/// Sends a single file descriptor over a Unix domain socket.
///
/// The control payload is deliberately one byte so the receiver can tell an fd
/// message from a child error frame before inspecting ancillary data.
fn send_fd(socket: RawFd, fd_to_send: RawFd) -> Result<()> {
    let payload = [FD_MESSAGE];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control = vec![0_u8; cmsg_space_for_fd()];

    let mut message = zeroed_msghdr();
    message.msg_iov = ptr::addr_of_mut!(iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    set_msg_controllen(&mut message, control.len())?;

    // SAFETY: message points to a valid iovec and control buffer sized with
    // CMSG_SPACE for one RawFd. The cmsg header is initialized before sendmsg.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(ptr::addr_of!(message));
        if cmsg.is_null() {
            bail!("failed to allocate fd-passing control message");
        }

        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(raw_fd_size_for_cmsg()) as _;
        ptr::write(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd_to_send);

        loop {
            let sent = libc::sendmsg(socket, ptr::addr_of!(message), libc::MSG_NOSIGNAL);
            if sent == -1 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                bail!("sendmsg failed while passing fd: {error}");
            }
            if sent != 1 {
                bail!("sendmsg wrote {sent} bytes while passing fd. Expected 1 byte.");
            }
            break;
        }
    }

    Ok(())
}

/// Receives the child's first control message.
///
/// On success this returns the seccomp notification fd transferred with
/// `SCM_RIGHTS`. If the child failed before installing seccomp, this reads and
/// surfaces the child error message instead.
fn recv_initial_child_message(socket: RawFd, child_pid: Option<libc::pid_t>) -> Result<OwnedFd> {
    let mut payload = [0_u8];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = vec![0_u8; cmsg_space_for_fd()];

    let mut message = zeroed_msghdr();
    message.msg_iov = ptr::addr_of_mut!(iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    set_msg_controllen(&mut message, control.len())?;

    let received = loop {
        let received = {
            // SAFETY: message points to valid payload and ancillary data buffers.
            unsafe { libc::recvmsg(socket, ptr::addr_of_mut!(message), libc::MSG_CMSG_CLOEXEC) }
        };

        if received == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            bail!("recvmsg failed while receiving fd: {error}");
        }
        break received;
    };
    if received == 0 {
        if let Some(child_pid) = child_pid {
            if let Some(status) = child_exit_summary(child_pid)
                .with_context(|| format!("failed to read child {child_pid} exit status"))?
            {
                bail!("Control socket closed before the fd arrived. Child {child_pid} {status}.");
            }

            bail!(
                "Control socket closed before the fd arrived. Child {child_pid} is still running."
            );
        }

        bail!("control socket closed before fd was received");
    }

    match payload[0] {
        FD_MESSAGE => {}
        ERROR_MESSAGE => {
            let message = read_child_error(socket).context("failed to read child setup error")?;
            bail!("child failed before sending notification fd: {message}");
        }
        byte => bail!("received unexpected child control message {byte}"),
    }

    // `MSG_CMSG_CLOEXEC` protects the parent side from leaking the received fd
    // through any future exec of the wrapper process itself.
    let fd = extract_received_fd(&message).context("missing SCM_RIGHTS fd in control message")?;
    let owned_fd = {
        // SAFETY: fd was received through SCM_RIGHTS and is now owned here.
        unsafe { OwnedFd::from_raw_fd(fd) }
    };

    Ok(owned_fd)
}

/// Reads a setup child exit status without blocking, if it is already available.
fn child_exit_summary(child_pid: libc::pid_t) -> Result<Option<String>> {
    let mut status = 0;

    loop {
        let waited_pid = {
            // SAFETY: waitpid writes to status and uses WNOHANG to avoid blocking.
            unsafe { libc::waitpid(child_pid, ptr::addr_of_mut!(status), libc::WNOHANG) }
        };

        if waited_pid == child_pid {
            return Ok(Some(describe_wait_status(status)));
        }
        if waited_pid == 0 {
            return Ok(None);
        }

        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(Some("is no longer waitable".to_owned()));
        }

        bail!("waitpid({child_pid}) failed: {error}");
    }
}

/// Converts a raw wait status into a human-readable child outcome.
fn describe_wait_status(status: i32) -> String {
    if libc::WIFEXITED(status) {
        return format!("exited with status {}", libc::WEXITSTATUS(status));
    }

    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        if let Some(name) = signal_name(signal) {
            return format!("terminated by signal {signal} ({name})");
        }

        return format!("terminated by signal {signal}");
    }

    format!("changed state with wait status {status}")
}

/// Names the signals most likely to explain early child setup failure.
fn signal_name(signal: i32) -> Option<&'static str> {
    match signal {
        libc::SIGABRT => Some("SIGABRT"),
        libc::SIGBUS => Some("SIGBUS"),
        libc::SIGFPE => Some("SIGFPE"),
        libc::SIGILL => Some("SIGILL"),
        libc::SIGKILL => Some("SIGKILL"),
        libc::SIGSEGV => Some("SIGSEGV"),
        libc::SIGSYS => Some("SIGSYS"),
        libc::SIGTERM => Some("SIGTERM"),
        _ => None,
    }
}

#[allow(clippy::cast_ptr_alignment)]
/// Extracts the first `SCM_RIGHTS` fd from a received control message.
fn extract_received_fd(message: &libc::msghdr) -> Option<RawFd> {
    // SAFETY: message was filled by recvmsg and remains valid while inspecting
    // its control headers.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(ptr::addr_of!(*message));
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET
                && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                && (*cmsg).cmsg_len >= libc::CMSG_LEN(raw_fd_size_for_cmsg()) as _
            {
                return Some(ptr::read(libc::CMSG_DATA(cmsg).cast::<RawFd>()));
            }

            cmsg = libc::CMSG_NXTHDR(ptr::addr_of!(*message), cmsg);
        }
    }

    None
}

/// Blocks until the parent writes the supervisor-ready byte.
fn wait_for_ready(socket: RawFd) -> Result<()> {
    let mut byte = [0_u8];
    read_exact(socket, &mut byte)?;

    if byte[0] != READY_BYTE {
        bail!("received unexpected supervisor ready byte {}", byte[0]);
    }

    Ok(())
}

/// Reads a child setup status frame after the parent releases the child.
///
/// This free function is `pub(crate)` so the async supervisor can call it from
/// a `tokio::task::spawn_blocking` closure using only the raw fd, without
/// needing to borrow the full `SessionProcess`.
pub(crate) fn read_child_setup_status_fd(socket: RawFd) -> Result<ChildSetupStatus> {
    let mut kind = [0_u8];
    let read_count = loop {
        let read_count = {
            // SAFETY: kind points to valid writable memory for one byte.
            unsafe { libc::read(socket, kind.as_mut_ptr().cast(), kind.len()) }
        };

        if read_count == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            bail!("failed to read child setup status: {error}");
        }

        break read_count;
    };
    if read_count == 0 {
        // The control socket is SOCK_CLOEXEC, so EOF after the ready signal is
        // the expected success path: exec replaced the child image.
        return Ok(ChildSetupStatus::ControlClosed);
    }

    match kind[0] {
        ERROR_MESSAGE => Ok(ChildSetupStatus::Failed(
            read_child_error(socket).context("failed to read child setup error")?,
        )),
        byte => bail!("received unexpected child setup status byte {byte}"),
    }
}

/// Sends a bounded UTF-8 child setup error over the control socket.
fn send_child_error(socket: RawFd, message: &str) -> Result<()> {
    let bytes = message.as_bytes();
    let len = u32::try_from(bytes.len()).context("child setup error message is too large")?;
    if len > MAX_CHILD_ERROR_LEN {
        bail!("child setup error message exceeds maximum length");
    }

    write_all(socket, &[ERROR_MESSAGE])?;
    write_all(socket, &len.to_be_bytes())?;
    write_all(socket, bytes)
}

/// Reads a bounded UTF-8 child setup error from the control socket.
fn read_child_error(socket: RawFd) -> Result<String> {
    let mut len = [0_u8; mem::size_of::<u32>()];
    read_exact(socket, &mut len).context("failed to read child error length")?;
    let len = u32::from_be_bytes(len);
    if len > MAX_CHILD_ERROR_LEN {
        bail!("child setup error length {len} exceeds maximum");
    }

    let len = usize::try_from(len).context("child setup error length does not fit usize")?;
    let mut message = vec![0_u8; len];
    read_exact(socket, &mut message).context("failed to read child error message")?;
    String::from_utf8(message).context("child setup error message is not valid UTF-8")
}

/// Drops from the wrapper's current credentials to the target login identity.
///
/// The wrapper normally starts privileged so it can set groups and UID for the
/// target user. Non-root smoke tests can already run as that identity. In that
/// case, there is nothing to drop.
fn drop_privileges(user: &str, gid: libc::gid_t, uid: libc::uid_t) -> Result<()> {
    // Non-root smoke tests often target the current user. Treat that as already
    // dropped so local integration checks do not require sudo just to exercise
    // the seccomp and lifecycle path.
    if current_effective_identity_matches(gid, uid) {
        return Ok(());
    }

    let username = CString::new(user).context("username contains an interior NUL byte")?;

    let setgid_result = {
        // SAFETY: setgid is called with the target gid supplied by the trusted
        // wrapper invoker before setuid permanently drops root privileges.
        unsafe { libc::setgid(gid) }
    };
    if setgid_result == -1 {
        bail!("setgid({gid}) failed: {}", io::Error::last_os_error());
    }

    let initgroups_result = {
        // SAFETY: username is NUL-terminated and gid is the target primary gid.
        unsafe { libc::initgroups(username.as_ptr(), gid) }
    };
    if initgroups_result == -1 {
        bail!("initgroups({user:?}, {gid}) failed: {}", io::Error::last_os_error());
    }

    let setuid_result = {
        // SAFETY: setuid is called last so a failure prevents command exec as root.
        unsafe { libc::setuid(uid) }
    };
    if setuid_result == -1 {
        bail!("setuid({uid}) failed: {}", io::Error::last_os_error());
    }

    Ok(())
}

/// Returns true when the current effective UID/GID already match the target.
fn current_effective_identity_matches(gid: libc::gid_t, uid: libc::uid_t) -> bool {
    let running_uid = {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    };
    let running_primary_gid = {
        // SAFETY: getegid has no preconditions.
        unsafe { libc::getegid() }
    };

    running_uid == uid && running_primary_gid == gid
}

/// Replaces the child process with the requested command.
///
/// This uses `execv` directly because the child is already forked, filtered,
/// and synchronized with the parent.
fn exec_command(command: &[String]) -> Result<()> {
    let program = command
        .first()
        .context("command vector must contain at least one entry")?;
    let cstrings: Vec<CString> = command
        .iter()
        .map(|arg| string_to_cstring(arg))
        .collect::<Result<_>>()?;
    let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(ptr::null());

    let result = {
        // SAFETY: cstrings and argv are NUL-terminated and live until execv
        // either replaces this process image or returns an error.
        unsafe { libc::execv(cstrings[0].as_ptr(), argv.as_ptr()) }
    };
    debug_assert_eq!(result, -1);
    bail!("execv({program}) failed: {}", io::Error::last_os_error());
}

/// Converts a command argument to a C string suitable for `execv`.
fn string_to_cstring(arg: &str) -> Result<CString> {
    CString::new(arg).context("command argument contains an interior NUL byte")
}

/// Reads exactly `buffer.len()` bytes from a raw fd. Retries automatically if a
/// signal interrupts the read.
fn read_exact(fd: RawFd, mut buffer: &mut [u8]) -> Result<()> {
    while !buffer.is_empty() {
        let read_count = {
            // SAFETY: buffer points to valid writable memory for buffer.len().
            unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) }
        };

        if read_count == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            bail!("read failed: {error}");
        }
        if read_count == 0 {
            bail!("unexpected EOF");
        }

        let read_count = usize::try_from(read_count)
            .context("internal error: read count negative after validation")?;
        buffer = &mut buffer[read_count..];
    }

    Ok(())
}

/// Writes the whole buffer to a raw fd. Retries automatically if a signal
/// interrupts the write.
fn write_all(fd: RawFd, mut buffer: &[u8]) -> Result<()> {
    while !buffer.is_empty() {
        let written = {
            // SAFETY: buffer points to valid readable memory for buffer.len().
            unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) }
        };

        if written == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            bail!("write failed: {error}");
        }
        if written == 0 {
            bail!("write returned 0 bytes");
        }

        let written = usize::try_from(written)
            .context("internal error: written count negative after validation")?;
        buffer = &buffer[written..];
    }

    Ok(())
}

/// Closes a raw fd that is not wrapped in an `OwnedFd`.
///
/// The seccomp listener fd is returned by `libseccomp-rs` as a raw descriptor,
/// then duplicated into the parent through `SCM_RIGHTS`. The child closes its
/// original copy explicitly with this helper.
fn close_fd(fd: RawFd) -> Result<()> {
    let result = {
        // SAFETY: fd is the raw seccomp notification descriptor returned by libseccomp.
        unsafe { libc::close(fd) }
    };
    if result == -1 {
        bail!("close({fd}) failed: {}", io::Error::last_os_error());
    }

    Ok(())
}

/// Returns the ancillary buffer size required to transfer one raw fd.
fn cmsg_space_for_fd() -> usize {
    // SAFETY: CMSG_SPACE is a pure size calculation for one RawFd payload.
    unsafe { libc::CMSG_SPACE(raw_fd_size_for_cmsg()) as usize }
}

#[allow(clippy::useless_conversion)]
/// Assigns `msghdr.msg_controllen` portably across libc implementations.
fn set_msg_controllen(message: &mut libc::msghdr, len: usize) -> Result<()> {
    // glibc exposes msg_controllen as usize, while musl exposes it as socklen_t
    // (u32 on x86_64). The fallible conversion keeps one implementation working
    // for both CI targets.
    message.msg_controllen = len
        .try_into()
        .context("control message buffer length does not fit msg_controllen")?;
    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
/// Returns the raw fd payload size in the type expected by `CMSG_SPACE`.
fn raw_fd_size_for_cmsg() -> libc::c_uint {
    mem::size_of::<RawFd>() as libc::c_uint
}

/// Creates an all-zero `msghdr` for later field-by-field initialization.
fn zeroed_msghdr() -> libc::msghdr {
    let message = MaybeUninit::<libc::msghdr>::zeroed();
    // SAFETY: an all-zero msghdr is the standard initialization pattern before
    // assigning the fields used by sendmsg/recvmsg.
    unsafe { message.assume_init() }
}

/// Marks the wrapper as a child subreaper for this process tree.
///
/// This lets the wrapper reap descendants that outlive the initial command.
/// Without this setting, the kernel reparents these descendants to PID 1, and
/// the wrapper loses visibility over them.
fn enable_child_subreaper() -> Result<()> {
    let result = {
        // SAFETY: prctl is called with PR_SET_CHILD_SUBREAPER and integer
        // arguments as documented by prctl(2).
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }
    };
    if result == -1 {
        bail!("prctl(PR_SET_CHILD_SUBREAPER) failed: {}", io::Error::last_os_error());
    }
    Ok(())
}

/// Reads the process group ID for a live process.
fn process_group_id(pid: libc::pid_t) -> Result<libc::pid_t> {
    let process_group_id = {
        // SAFETY: getpgid reads process metadata for the supplied pid.
        unsafe { libc::getpgid(pid) }
    };
    if process_group_id == -1 {
        bail!("getpgid({pid}) failed: {}", io::Error::last_os_error());
    }
    Ok(process_group_id)
}

/// Reads the session ID for a live process.
fn session_id(pid: libc::pid_t) -> Result<libc::pid_t> {
    let session_id = {
        // SAFETY: getsid reads process metadata for the supplied pid.
        unsafe { libc::getsid(pid) }
    };
    if session_id == -1 {
        bail!("getsid({pid}) failed: {}", io::Error::last_os_error());
    }
    Ok(session_id)
}

/// Reaps all currently exited child or subreaped descendant processes.
///
/// The return value also tells the supervisor whether any children remain. That
/// signal is necessary because live descendants can remain even when no PIDs
/// were reaped in this pass.
pub(crate) fn reap_available_children() -> Result<ReapStatus> {
    let mut reaped = Vec::new();

    loop {
        let mut status = 0;
        let pid = {
            // SAFETY: waitpid writes to status and uses WNOHANG to avoid blocking.
            unsafe { libc::waitpid(-1, ptr::addr_of_mut!(status), libc::WNOHANG) }
        };

        if pid > 0 {
            reaped.push(ReapedProcess { pid, status });
            continue;
        }
        if pid == 0 {
            // No exits are pending. `waitpid` reports that at least one child or
            // subreaped descendant still needs supervision.
            return Ok(ReapStatus {
                reaped,
                has_children: true,
            });
        }

        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            // No children remain. The supervisor can now close the notification
            // fd without stranding a descendant that inherited the seccomp
            // filter.
            return Ok(ReapStatus {
                reaped,
                has_children: false,
            });
        }
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        bail!("waitpid failed while reaping children: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        describe_wait_status, string_to_cstring, read_child_setup_status_fd,
        recv_initial_child_message, send_child_error, send_fd, socket_pair, ChildSetupStatus,
    };
    use std::io::Error;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use anyhow::{bail, Result};

    #[test]
    fn passes_file_descriptor_over_unix_socket() {
        let (sender, receiver) = socket_pair().expect("failed to create the socket pair");
        let (pipe_reader, pipe_writer) = pipe().expect("failed to create the pipe");

        send_fd(sender.as_raw_fd(), pipe_reader.as_raw_fd()).expect("failed to send the fd");
        let received_reader = recv_initial_child_message(receiver.as_raw_fd(), None)
            .expect("failed to receive the fd");

        super::write_all(pipe_writer.as_raw_fd(), b"x").expect("failed to write to the pipe");
        let mut byte = [0_u8];
        super::read_exact(received_reader.as_raw_fd(), &mut byte)
            .expect("failed to read from the pipe");

        assert_eq!(byte, [b'x']);
    }

    #[test]
    fn string_to_cstring_rejects_nul_bytes() {
        let arg = "bad\0arg";

        assert!(string_to_cstring(arg).is_err());
    }

    #[test]
    fn ready_signal_uses_expected_byte() {
        let (parent, child) = socket_pair().expect("failed to create the socket pair");

        signal_ready_for_test(parent.as_raw_fd()).expect("failed to write the ready byte");
        super::wait_for_ready(child.as_raw_fd()).expect("failed to accept the ready byte");
    }

    #[test]
    fn pre_fd_child_error_is_reported_to_parent() {
        let (parent, child) = socket_pair().expect("failed to create the socket pair");

        send_child_error(child.as_raw_fd(), "setup failed").expect("failed to send the error");
        let error = recv_initial_child_message(parent.as_raw_fd(), None)
            .expect_err("the fd receive succeeded");

        assert!(error.to_string().contains("setup failed"));
    }

    #[test]
    fn wait_status_describes_signal_death() {
        let signal_status = libc::SIGSEGV;

        assert_eq!(describe_wait_status(signal_status), "terminated by signal 11 (SIGSEGV)");
    }

    #[test]
    fn post_ready_child_error_is_reported_to_parent() {
        let (parent, child) = socket_pair().expect("failed to create the socket pair");

        send_child_error(child.as_raw_fd(), "drop privileges failed")
            .expect("failed to send the error");
        let status =
            read_child_setup_status_fd(parent.as_raw_fd()).expect("failed to read the status");

        assert_eq!(status, ChildSetupStatus::Failed("drop privileges failed".to_owned()));
    }

    #[test]
    fn closed_control_socket_marks_exec_boundary() {
        let (parent, child) = socket_pair().expect("failed to create the socket pair");

        drop(child);
        let status =
            read_child_setup_status_fd(parent.as_raw_fd()).expect("failed to read the status");

        assert_eq!(status, ChildSetupStatus::ControlClosed);
    }

    fn signal_ready_for_test(fd: RawFd) -> Result<()> {
        super::write_all(fd, &[super::READY_BYTE])
    }

    fn pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [-1; 2];
        let result = {
            // SAFETY: pipe initializes both entries in fds on success.
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }
        };
        if result == -1 {
            bail!("pipe failed: {}", Error::last_os_error());
        }

        let reader = {
            // SAFETY: pipe2 returned a valid owned fd at fds[0].
            unsafe { OwnedFd::from_raw_fd(fds[0]) }
        };
        let writer = {
            // SAFETY: pipe2 returned a valid owned fd at fds[1].
            unsafe { OwnedFd::from_raw_fd(fds[1]) }
        };

        Ok((reader, writer))
    }
}
