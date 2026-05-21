//! Reads syscall arguments from a supervised process's virtual memory.
//!
//! # Background: seccomp user notifications and process memory
//!
//! When the kernel intercepts a syscall via a seccomp user notification filter,
//! the target process is **frozen** at the syscall boundary. Its virtual memory
//! is stable and readable by the supervisor process through the
//! `/proc/[pid]/mem` pseudo-file, without needing `ptrace` attach (which would
//! interfere with the existing seccomp relationship).
//!
//! This module uses [`pread(2)`] rather than [`read(2)`] on that pseudo-file
//! so each read is positioned by virtual address without having to `lseek`. The
//! kernel maps the target process's address space into the read offset of the
//! pseudo-file, so reading at offset `N` returns the byte at virtual address
//! `N`.
//!
//! # TOCTOU mitigation
//!
//! Between receiving a notification and reading memory, the target process
//! could in theory be killed or have its syscall cancelled by a signal. The
//! supervisor calls `check_notification_valid` before and
//! during each read to detect this condition early. If the notification becomes
//! invalid, reading stops and the supervisor can skip sending a response
//! (the kernel has already cleaned up the frozen syscall).
//!
//! [`pread(2)`]: https://man7.org/linux/man-pages/man2/pread.2.html
//! [`read(2)`]: https://man7.org/linux/man-pages/man2/read.2.html
#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use anyhow::{Context, Result, bail};
use libseccomp::{ScmpFd, ScmpNotifReq, ScmpSyscall};

use super::supervisor::check_notification_valid;

/// Maximum length of a single NUL-terminated string read from process memory.
///
/// Linux limits executable pathnames to `PATH_MAX` (4 096 bytes). Individual
/// argv entries can be larger but we apply the same cap for safety. Strings
/// longer than this limit are treated as an error.
const MAX_STRING_LEN: usize = 4096;

/// Maximum number of argv entries read from the target process.
///
/// Real commands rarely approach this. The limit prevents a pathological argv
/// from looping the supervisor indefinitely.
const MAX_ARGV_ENTRIES: usize = 256;

// ── pread wrapper ────────────────────────────────────────────────────────────

/// Reads up to `buf.len()` bytes from file descriptor `fd` starting at
/// absolute byte offset `offset`, without moving the fd's file position.
///
/// This is a direct wrapper around the `pread(2)` system call. We use it
/// instead of `seek + read` because each call is atomic with respect to the
/// file offset, and because `/proc/[pid]/mem` requires this approach — the
/// kernel maps the target's virtual address space into the file's offset space.
///
/// Returns the number of bytes actually read (may be less than requested).
fn pread(fd: RawFd, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    // SAFETY: `buf` is a valid mutable slice for the duration of the call.
    // `fd` is a valid file descriptor owned by the caller. The offset is cast
    // to `off_t`; on x86_64 Linux, `off_t` is i64.  We return an error if the
    // address overflows i64 so we never read from an unintended location.
    let offset_i64 = i64::try_from(offset).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("virtual address {offset:#x} overflows off_t (i64)"),
        )
    })?;

    let result =
        unsafe { libc::pread(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), offset_i64) };

    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(usize::try_from(result).unwrap_or(0))
    }
}

// ── string reader ────────────────────────────────────────────────────────────

/// Opens `/proc/[pid]/mem` for reading and returns the file handle.
///
/// The caller should open the file once per notification and pass the raw fd
/// to the reading functions to avoid repeated open/close overhead.
fn open_proc_mem(pid: u32) -> Result<File> {
    let path = format!("/proc/{pid}/mem");
    File::open(&path).with_context(|| format!("failed to open {path}"))
}

/// Reads a NUL-terminated C string from another process's virtual memory.
///
/// # How it works
///
/// 1. Opens `/proc/[pid]/mem`.
/// 2. Uses [`pread(2)`](pread) to read 256-byte chunks starting at `addr`.
/// 3. Scans each chunk for a NUL byte (`\0`), which terminates C strings.
/// 4. Accumulates bytes into a `String` until the NUL or [`MAX_STRING_LEN`]
///    is reached.
///
/// # Arguments
///
/// * `pid`  – PID of the target process (must be frozen at a seccomp boundary).
/// * `addr` – Virtual address of the first character of the string.
///
/// # Errors
///
/// - I/O errors from `open` or `pread`.
/// - EOF reached before a NUL terminator (the string is not NUL-terminated,
///   which is structurally invalid for a C string argument to execve).
/// - Strings longer than [`MAX_STRING_LEN`].
/// - Bytes that are not valid UTF-8 (exec paths should always be valid UTF-8
///   on modern Linux; we reject anything else to keep the rest of the code
///   clean).
pub(crate) fn read_string_from_process(pid: u32, addr: u64) -> Result<String> {
    let file = open_proc_mem(pid)?;
    let fd = file.as_raw_fd();

    let mut result = Vec::with_capacity(128);
    let mut offset = addr;
    let mut chunk = [0u8; 256];

    loop {
        let n = pread(fd, &mut chunk, offset)
            .with_context(|| format!("pread /proc/{pid}/mem at {offset:#x}"))?;

        if n == 0 {
            // EOF before finding a NUL terminator.  This is a structural error:
            // a C string argument to execve must be NUL-terminated.  Treating
            // the truncated bytes as the path would risk misidentifying the
            // executable (e.g. an allowlisted prefix of a longer path).
            bail!(
                "pread /proc/{pid}/mem at {offset:#x}: EOF before NUL terminator \
                 (string starting at {addr:#x} is not NUL-terminated)"
            );
        }

        for &byte in &chunk[..n] {
            if byte == 0 {
                // Found the NUL terminator: convert and return.
                return String::from_utf8(result).with_context(|| {
                    format!("string in process {pid} at {addr:#x} is not valid UTF-8")
                });
            }
            result.push(byte);
            if result.len() > MAX_STRING_LEN {
                bail!(
                    "string in process {pid} at {addr:#x} exceeds maximum length \
                     ({MAX_STRING_LEN} bytes)"
                );
            }
        }

        offset += n as u64;
    }
}

// ── argv reader ──────────────────────────────────────────────────────────────

/// Reads the argv array for an intercepted exec syscall.
///
/// On `x86_64`, the argv passed to `execve`/`execveat` is a `char *const *`:
/// a pointer to a NULL-terminated array of pointers to NUL-terminated strings.
/// This function walks that pointer chain and collects each argument string.
///
/// # TOCTOU bracketing
///
/// The notification is validated with [`check_notification_valid`] between each
/// pointer read so that if the target process is killed mid-way, we detect it
/// quickly rather than reading stale or remapped memory.
///
/// # Arguments
///
/// * `notif_fd`  – The seccomp notification file descriptor.
/// * `notif_id`  – The ID from the current [`ScmpNotifReq`], used for
///   validity checks.
/// * `pid`       – PID of the process that triggered the notification.
/// * `argv_addr` – Virtual address of the `char **argv` argument.
fn read_argv(
    notif_fd: ScmpFd,
    notification_id: u64,
    pid: u32,
    argv_addr: u64,
) -> Result<Vec<String>> {
    let file = open_proc_mem(pid)?;
    let fd = file.as_raw_fd();

    let mut args = Vec::new();
    // Each entry in argv is one pointer (8 bytes on x86_64). We walk the array
    // by incrementing the offset by pointer size (8) on each iteration.
    let pointer_size: u64 = 8;
    let mut ptr_offset = argv_addr;

    loop {
        // Read one pointer from the argv array.
        let mut ptr_bytes = [0u8; 8];
        let n = pread(fd, &mut ptr_bytes, ptr_offset)
            .with_context(|| format!("pread argv pointer at {ptr_offset:#x} in pid {pid}"))?;

        if n < 8 {
            // Partial read at end of mapping — treat as NULL terminator.
            break;
        }

        // x86_64 is little-endian; interpret the 8 bytes as a virtual address.
        let arg_ptr = u64::from_le_bytes(ptr_bytes);
        if arg_ptr == 0 {
            // NULL pointer marks the end of the argv array.
            break;
        }

        // Check that the notification is still valid before dereferencing the
        // pointer. If the process was killed between reading the argv array
        // header and dereferencing an entry, this detects it.
        check_notification_valid(notif_fd, notification_id)
            .context("notification became invalid while reading argv entries")?;

        let arg = read_string_from_process(pid, arg_ptr)
            .with_context(|| format!("failed to read argv[{}] from process {pid}", args.len()))?;
        args.push(arg);

        if args.len() >= MAX_ARGV_ENTRIES {
            bail!(
                "process {pid} argv has more than {MAX_ARGV_ENTRIES} entries; \
                 refusing to read further"
            );
        }

        ptr_offset += pointer_size;
    }

    Ok(args)
}

// ── public interface ─────────────────────────────────────────────────────────

/// Reads the executable path and argument vector for an intercepted exec syscall.
///
/// # Syscall argument layout (`x86_64`)
///
/// | Syscall    | arg\[0\] | arg\[1\]     | arg\[2\] |
/// |------------|----------|--------------|----------|
/// | `execve`   | filename | argv pointer | envp     |
/// | `execveat` | dirfd    | pathname     | argv     |
///
/// For `execveat`, `arg[0]` is an integer (the `dirfd`), not a pointer. The
/// filename starts at `arg[1]`.
///
/// # Return value
///
/// Returns `(executable_path, argv, filename_addr)` where `argv` is the full
/// argument vector including `argv[0]` (which may differ from the executable
/// path).
///
/// # TOCTOU mitigation
///
/// The notification validity is checked before the filename read, between the
/// filename and argv reads, and between each argv entry. If the notification
/// becomes invalid at any of those points, the error propagates to the caller,
/// which should skip sending a response for this notification (the kernel has
/// already cleaned up the frozen syscall).
///
/// # Errors
///
/// I/O failures reading from `/proc/[pid]/mem`, oversized strings, and
/// notification invalidity all produce errors.
///
/// On success, returns `(exec_path, argv, filename_addr)`. The caller can
/// use `filename_addr` with [`verify_exec_path_unchanged`] to re-read the
/// path just before sending `CONTINUE`, shrinking the TOCTOU window.
pub(crate) fn read_exec_args(
    notif_fd: ScmpFd,
    pid: u32,
    req: &ScmpNotifReq,
) -> Result<(String, Vec<String>, u64)> {
    // Resolve syscall names to their numeric IDs once.  `from_name` resolves
    // against the running kernel's syscall table, so this is always correct
    // for the current architecture.
    let execve =
        ScmpSyscall::from_name("execve").context("failed to resolve execve syscall number")?;
    let execveat =
        ScmpSyscall::from_name("execveat").context("failed to resolve execveat syscall number")?;

    let (filename_addr, argv_addr) = if req.data.syscall == execve {
        // execve(const char *filename, char *const argv[], char *const envp[])
        //         args[0]             args[1]
        (req.data.args[0], req.data.args[1])
    } else if req.data.syscall == execveat {
        // execveat(int dirfd, const char *pathname, char *const argv[], ...)
        //                     args[1]               args[2]
        (req.data.args[1], req.data.args[2])
    } else {
        bail!("unexpected non-exec syscall notification: {}", req.data.syscall);
    };

    // Bracket the filename read between two validity checks. If the target
    // process dies between receiving the notification and reading memory, we
    // detect it here rather than reading garbage.
    check_notification_valid(notif_fd, req.id)
        .context("notification became invalid before reading executable path")?;

    let filename = read_string_from_process(pid, filename_addr).with_context(|| {
        format!("failed to read exec filename from process {pid} at {filename_addr:#x}")
    })?;

    check_notification_valid(notif_fd, req.id)
        .context("notification became invalid before reading argv")?;

    let argv = read_argv(notif_fd, req.id, pid, argv_addr)?;

    Ok((filename, argv, filename_addr))
}

/// Re-reads the exec path from process memory and verifies it has not changed.
///
/// This is the primary TOCTOU mitigation for `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
/// The supervisor calls this **immediately before** sending the `CONTINUE`
/// response, after the authorization decision has been made. If the path has
/// changed between the original read (used for authorization) and this re-read,
/// a racing thread in the child process has swapped the filename buffer and the
/// exec must be denied.
///
/// This does not eliminate the TOCTOU window entirely — there is still a small
/// gap between this re-read and the kernel's resume of the syscall — but it
/// shrinks it from the full authorization round-trip (potentially milliseconds)
/// to a single `pread` + `ioctl` (microseconds). Combined with the `userfaultfd`
/// deny rule (which prevents deterministic control of the race), this makes
/// exploitation extremely difficult in practice.
///
/// Returns `Ok(())` if the path is unchanged, or an error describing the
/// mismatch.
pub(crate) fn verify_exec_path_unchanged(
    pid: u32,
    filename_addr: u64,
    expected_path: &str,
) -> Result<()> {
    let current_path = read_string_from_process(pid, filename_addr).with_context(|| {
        format!("TOCTOU re-read: failed to read exec path from process {pid} at {filename_addr:#x}")
    })?;

    if current_path != expected_path {
        bail!(
            "TOCTOU detected: exec path changed between authorization and response \
             (was {expected_path:?}, now {current_path:?}) in pid {pid}"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests for `pread` and string reading require an actual process, which is
    // impractical in a pure unit-test context without spawning children and
    // installing seccomp filters.  The integration behaviour is covered by the
    // supervisor loop tests and by manual end-to-end testing described in
    // README.md.
    //
    // We do test the pure-logic helpers that do not require live process memory.

    use super::MAX_ARGV_ENTRIES;
    use super::MAX_STRING_LEN;

    #[test]
    fn constants_are_sane() {
        // Use const blocks to avoid clippy::assertions_on_constants.
        const { assert!(MAX_STRING_LEN >= 4096) };
        const { assert!(MAX_ARGV_ENTRIES >= 1) };
    }
}
