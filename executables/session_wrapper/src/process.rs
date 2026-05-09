#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use anyhow::{bail, Context, Result};

use super::seccomp;

const READY_BYTE: u8 = b'R';
const FD_MESSAGE: u8 = b'F';
const ERROR_MESSAGE: u8 = b'E';
const MAX_CHILD_ERROR_LEN: u32 = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct ChildProcessConfig {
    pub(crate) shell: PathBuf,
    pub(crate) user: String,
    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::gid_t,
    pub(crate) intercept_fork: bool,
}

#[derive(Debug)]
pub(crate) struct SessionProcess {
    child_pid: libc::pid_t,
    child_process_group_id: libc::pid_t,
    child_session_id: libc::pid_t,
    notification_fd: OwnedFd,
    control_socket: OwnedFd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChildSetupStatus {
    ControlClosed,
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReapedProcess {
    pub(crate) pid: libc::pid_t,
    pub(crate) status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReapStatus {
    pub(crate) reaped: Vec<ReapedProcess>,
    pub(crate) has_children: bool,
}

impl SessionProcess {
    pub(crate) fn child_pid(&self) -> libc::pid_t {
        self.child_pid
    }

    pub(crate) fn child_process_group_id(&self) -> libc::pid_t {
        self.child_process_group_id
    }

    pub(crate) fn child_session_id(&self) -> libc::pid_t {
        self.child_session_id
    }

    pub(crate) fn notification_fd(&self) -> RawFd {
        self.notification_fd.as_raw_fd()
    }

    pub(crate) fn control_socket_fd(&self) -> RawFd {
        self.control_socket.as_raw_fd()
    }

    pub(crate) fn signal_supervisor_ready(&self) -> Result<()> {
        write_all(self.control_socket.as_raw_fd(), &[READY_BYTE])
            .context("failed to signal child that supervisor is ready")
    }

    pub(crate) fn read_child_setup_status(&self) -> Result<ChildSetupStatus> {
        read_child_setup_status(self.control_socket.as_raw_fd())
    }
}

pub(crate) fn spawn_session(config: ChildProcessConfig) -> Result<SessionProcess> {
    enable_child_subreaper().context("failed to mark session-wrapper as child subreaper")?;

    let (parent_socket, child_socket) =
        socket_pair().context("failed to create control socketpair")?;

    let fork_result = {
        // SAFETY: fork has no Rust wrapper. This call happens before any threads
        // are started by session-wrapper; both branches immediately close the
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
            let notification_fd = recv_initial_child_message(parent_socket.as_raw_fd())
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

fn run_child(control_socket: &OwnedFd, config: &ChildProcessConfig) -> Result<()> {
    let notification_fd = seccomp::install_filter(config.intercept_fork)
        .context("failed to install session-wrapper seccomp filter in child")?;
    send_fd(control_socket.as_raw_fd(), notification_fd)
        .context("failed to send seccomp notification fd to parent")?;
    close_fd(notification_fd).context("failed to close child copy of seccomp notification fd")?;

    wait_for_ready(control_socket.as_raw_fd())
        .context("failed to receive supervisor ready byte")?;
    drop_privileges(&config.user, config.gid, config.uid).with_context(|| {
        format!(
            "failed to drop privileges to user {} (uid {}, gid {})",
            config.user, config.uid, config.gid
        )
    })?;

    exec_shell(&config.shell)
}

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
                bail!("sendmsg wrote {sent} bytes while passing fd; expected 1");
            }
            break;
        }
    }

    Ok(())
}

fn recv_initial_child_message(socket: RawFd) -> Result<OwnedFd> {
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

    let fd = extract_received_fd(&message).context("missing SCM_RIGHTS fd in control message")?;
    let owned_fd = {
        // SAFETY: fd was received through SCM_RIGHTS and is now owned here.
        unsafe { OwnedFd::from_raw_fd(fd) }
    };

    Ok(owned_fd)
}

#[allow(clippy::cast_ptr_alignment)]
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

fn wait_for_ready(socket: RawFd) -> Result<()> {
    let mut byte = [0_u8];
    read_exact(socket, &mut byte)?;

    if byte[0] != READY_BYTE {
        bail!("received unexpected supervisor ready byte {}", byte[0]);
    }

    Ok(())
}

fn read_child_setup_status(socket: RawFd) -> Result<ChildSetupStatus> {
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
        return Ok(ChildSetupStatus::ControlClosed);
    }

    match kind[0] {
        ERROR_MESSAGE => Ok(ChildSetupStatus::Failed(
            read_child_error(socket).context("failed to read child setup error")?,
        )),
        byte => bail!("received unexpected child setup status byte {byte}"),
    }
}

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

fn drop_privileges(user: &str, gid: libc::gid_t, uid: libc::uid_t) -> Result<()> {
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
        // SAFETY: setuid is called last so a failure prevents shell exec as root.
        unsafe { libc::setuid(uid) }
    };
    if setuid_result == -1 {
        bail!("setuid({uid}) failed: {}", io::Error::last_os_error());
    }

    Ok(())
}

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

fn exec_shell(shell: &Path) -> Result<()> {
    let shell_cstr = path_to_cstring(shell).context("shell path is not a valid C string")?;
    let argv = [shell_cstr.as_ptr(), ptr::null()];

    let result = {
        // SAFETY: shell_cstr and argv are NUL-terminated and live until execv
        // either replaces this process image or returns an error.
        unsafe { libc::execv(shell_cstr.as_ptr(), argv.as_ptr()) }
    };
    debug_assert_eq!(result, -1);
    bail!("execv({}) failed: {}", shell.display(), io::Error::last_os_error());
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).context("path contains an interior NUL byte")
}

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

fn cmsg_space_for_fd() -> usize {
    // SAFETY: CMSG_SPACE is a pure size calculation for one RawFd payload.
    unsafe { libc::CMSG_SPACE(raw_fd_size_for_cmsg()) as usize }
}

#[allow(clippy::useless_conversion)]
fn set_msg_controllen(message: &mut libc::msghdr, len: usize) -> Result<()> {
    message.msg_controllen = len
        .try_into()
        .context("control message buffer length does not fit msg_controllen")?;
    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
fn raw_fd_size_for_cmsg() -> libc::c_uint {
    mem::size_of::<RawFd>() as libc::c_uint
}

fn zeroed_msghdr() -> libc::msghdr {
    let message = MaybeUninit::<libc::msghdr>::zeroed();
    // SAFETY: an all-zero msghdr is the standard initialization pattern before
    // assigning the fields used by sendmsg/recvmsg.
    unsafe { message.assume_init() }
}

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
            return Ok(ReapStatus {
                reaped,
                has_children: true,
            });
        }

        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
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

pub(crate) fn process_exists(pid: libc::pid_t) -> Result<bool> {
    if pid <= 0 {
        return Ok(false);
    }

    let result = {
        // SAFETY: kill(pid, 0) performs existence/permission checking only.
        unsafe { libc::kill(pid, 0) }
    };

    if result == 0 {
        return Ok(true);
    }

    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => bail!("kill({pid}, 0) failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        path_to_cstring, read_child_setup_status, recv_initial_child_message, send_child_error,
        send_fd, socket_pair, ChildSetupStatus,
    };
    use std::io::Error;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::path::PathBuf;

    use anyhow::{bail, Result};

    #[test]
    fn passes_file_descriptor_over_unix_socket() {
        let (sender, receiver) = socket_pair().expect("socketpair should be created");
        let (pipe_reader, pipe_writer) = pipe().expect("pipe should be created");

        send_fd(sender.as_raw_fd(), pipe_reader.as_raw_fd()).expect("fd should be sent");
        let received_reader =
            recv_initial_child_message(receiver.as_raw_fd()).expect("fd should be received");

        super::write_all(pipe_writer.as_raw_fd(), b"x").expect("pipe write should succeed");
        let mut byte = [0_u8];
        super::read_exact(received_reader.as_raw_fd(), &mut byte)
            .expect("pipe read should succeed");

        assert_eq!(byte, [b'x']);
    }

    #[test]
    fn path_to_cstring_rejects_nul_bytes() {
        let path = PathBuf::from("bad\0path");

        assert!(path_to_cstring(&path).is_err());
    }

    #[test]
    fn ready_signal_uses_expected_byte() {
        let (parent, child) = socket_pair().expect("socketpair should be created");

        signal_ready_for_test(parent.as_raw_fd()).expect("ready byte should be written");
        super::wait_for_ready(child.as_raw_fd()).expect("ready byte should be accepted");
    }

    #[test]
    fn pre_fd_child_error_is_reported_to_parent() {
        let (parent, child) = socket_pair().expect("socketpair should be created");

        send_child_error(child.as_raw_fd(), "setup failed").expect("error should be sent");
        let error =
            recv_initial_child_message(parent.as_raw_fd()).expect_err("fd receive should fail");

        assert!(error.to_string().contains("setup failed"));
    }

    #[test]
    fn post_ready_child_error_is_reported_to_parent() {
        let (parent, child) = socket_pair().expect("socketpair should be created");

        send_child_error(child.as_raw_fd(), "drop privileges failed")
            .expect("error should be sent");
        let status =
            read_child_setup_status(parent.as_raw_fd()).expect("status should be readable");

        assert_eq!(status, ChildSetupStatus::Failed("drop privileges failed".to_owned()));
    }

    #[test]
    fn closed_control_socket_marks_exec_boundary() {
        let (parent, child) = socket_pair().expect("socketpair should be created");

        drop(child);
        let status =
            read_child_setup_status(parent.as_raw_fd()).expect("status should be readable");

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
