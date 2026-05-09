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
    notification_fd: OwnedFd,
    control_socket: OwnedFd,
}

impl SessionProcess {
    pub(crate) fn child_pid(&self) -> libc::pid_t {
        self.child_pid
    }

    pub(crate) fn notification_fd(&self) -> RawFd {
        self.notification_fd.as_raw_fd()
    }

    pub(crate) fn control_socket_fd(&self) -> RawFd {
        self.control_socket.as_raw_fd()
    }

    #[allow(dead_code)]
    pub(crate) fn signal_supervisor_ready(&self) -> Result<()> {
        write_all(self.control_socket.as_raw_fd(), &[READY_BYTE])
            .context("failed to signal child that supervisor is ready")
    }
}

pub(crate) fn spawn_session(config: ChildProcessConfig) -> Result<SessionProcess> {
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
            let notification_fd = recv_fd(parent_socket.as_raw_fd())
                .context("failed to receive seccomp notification fd from child")?;

            Ok(SessionProcess {
                child_pid,
                notification_fd,
                control_socket: parent_socket,
            })
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn run_child_or_exit(control_socket: OwnedFd, config: ChildProcessConfig) -> ! {
    if let Err(error) = run_child(&control_socket, &config) {
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
    let payload = [0_u8];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control = vec![0_u8; cmsg_space_for_fd()];

    let mut message = zeroed_msghdr();
    message.msg_iov = ptr::addr_of_mut!(iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();

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

        let sent = libc::sendmsg(socket, ptr::addr_of!(message), libc::MSG_NOSIGNAL);
        if sent == -1 {
            bail!("sendmsg failed while passing fd: {}", io::Error::last_os_error());
        }
        if sent != 1 {
            bail!("sendmsg wrote {sent} bytes while passing fd; expected 1");
        }
    }

    Ok(())
}

fn recv_fd(socket: RawFd) -> Result<OwnedFd> {
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
    message.msg_controllen = control.len();

    let received = {
        // SAFETY: message points to valid payload and ancillary data buffers.
        unsafe { libc::recvmsg(socket, ptr::addr_of_mut!(message), libc::MSG_CMSG_CLOEXEC) }
    };

    if received == -1 {
        bail!("recvmsg failed while receiving fd: {}", io::Error::last_os_error());
    }
    if received == 0 {
        bail!("control socket closed before fd was received");
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

fn drop_privileges(user: &str, gid: libc::gid_t, uid: libc::uid_t) -> Result<()> {
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
            .context("read returned a negative byte count after success")?;
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
            .context("write returned a negative byte count after success")?;
        buffer = &buffer[written..];
    }

    Ok(())
}

fn cmsg_space_for_fd() -> usize {
    // SAFETY: CMSG_SPACE is a pure size calculation for one RawFd payload.
    unsafe { libc::CMSG_SPACE(raw_fd_size_for_cmsg()) as usize }
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

#[cfg(test)]
mod tests {
    use super::{path_to_cstring, recv_fd, send_fd, socket_pair};
    use std::io::Error;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::PathBuf;

    use anyhow::{bail, Result};

    #[test]
    fn passes_file_descriptor_over_unix_socket() {
        let (sender, receiver) = socket_pair().expect("socketpair should be created");
        let (pipe_reader, pipe_writer) = pipe().expect("pipe should be created");

        send_fd(sender.as_raw_fd(), pipe_reader.as_raw_fd()).expect("fd should be sent");
        let received_reader = recv_fd(receiver.as_raw_fd()).expect("fd should be received");

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

    fn signal_ready_for_test(fd: i32) -> Result<()> {
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
