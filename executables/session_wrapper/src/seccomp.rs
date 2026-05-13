//! Seccomp policy construction for the session wrapper.
//!
//! The filter is intentionally narrow: default allow, notify on exec-family
//! syscalls, and deny known syscall families that can undermine command
//! authorization. That gives the parent wrapper the decision points needed for
//! command authorization without attempting to sandbox the entire session.
//!
//! `libseccomp-rs` owns the low-level BPF generation. This module only defines
//! the policy in syscall terms and returns the user-notification listener fd to
//! the process lifecycle code.
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};
use libseccomp::{check_api, ScmpAction, ScmpFilterContext, ScmpSyscall, ScmpVersion};

static FILTER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Action applied to one syscall rule in the wrapper policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    /// Route the syscall through seccomp user notification.
    Notify,

    /// Fail the syscall immediately with the supplied errno.
    Errno(i32),
}

/// Declarative syscall policy entry before it is resolved by `libseccomp-rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyscallRule {
    /// Linux syscall name resolved through `libseccomp-rs`.
    name: &'static str,

    /// Action to apply when this syscall is reached.
    action: RuleAction,
}

/// Builds the list of syscall rules for the wrapper policy.
///
/// Exec-family notifications are always installed because they are the command
/// authorization boundary. Fork-like syscalls are not notified because they do
/// not carry command material; descendants inherit this filter and are mediated
/// when they later call `execve` or `execveat`.
fn syscall_rules() -> Vec<SyscallRule> {
    vec![
        SyscallRule {
            name: "ptrace",
            action: RuleAction::Errno(libc::EPERM),
        },
        // Cross-process memory access (ptrace equivalents): deterministic
        // TOCTOU exploitation via a cooperating process overwriting the
        // frozen process's execve filename after the supervisor reads it.
        SyscallRule {
            name: "process_vm_writev",
            action: RuleAction::Errno(libc::EPERM),
        },
        SyscallRule {
            name: "process_vm_readv",
            action: RuleAction::Errno(libc::EPERM),
        },
        // pidfd_getfd can steal the seccomp notification fd from the
        // supervisor, subverting the entire authorization model.
        SyscallRule {
            name: "pidfd_getfd",
            action: RuleAction::Errno(libc::EPERM),
        },
        // userfaultfd makes the inherent seccomp unotify TOCTOU race
        // deterministic by controlling page-fault resolution timing.
        // Without it the race is probabilistic and hard to exploit.
        SyscallRule {
            name: "userfaultfd",
            action: RuleAction::Errno(libc::EPERM),
        },
        // Namespace creation: user + mount namespaces allow bind-mounting
        // a malicious binary over an allowlisted path, making path-based
        // checks meaningless.
        SyscallRule {
            name: "unshare",
            action: RuleAction::Errno(libc::EPERM),
        },
        SyscallRule {
            name: "setns",
            action: RuleAction::Errno(libc::EPERM),
        },
        // Mount operations (legacy and new APIs): bind mounts can shadow
        // any path in the filesystem.
        SyscallRule {
            name: "mount",
            action: RuleAction::Errno(libc::EPERM),
        },
        SyscallRule {
            name: "umount2",
            action: RuleAction::Errno(libc::EPERM),
        },
        SyscallRule {
            name: "mount_setattr",
            action: RuleAction::Errno(libc::EPERM),
        },
        SyscallRule {
            name: "fsopen",
            action: RuleAction::Errno(libc::EPERM),
        },
        SyscallRule {
            name: "fsmount",
            action: RuleAction::Errno(libc::EPERM),
        },
        SyscallRule {
            name: "move_mount",
            action: RuleAction::Errno(libc::EPERM),
        },
        SyscallRule {
            name: "execve",
            action: RuleAction::Notify,
        },
        SyscallRule {
            name: "execveat",
            action: RuleAction::Notify,
        },
    ]
}

/// Builds, but does not load, the `libseccomp-rs` filter context.
///
/// Tests use this to inspect/export the generated policy without installing a
/// filter into the test process.
fn build_filter() -> Result<ScmpFilterContext> {
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow)
        .context("failed to create libseccomp filter context")?;

    filter
        .set_ctl_nnp(true)
        .context("failed to enable no_new_privs on seccomp filter")?;

    for rule in syscall_rules() {
        let syscall = ScmpSyscall::from_name(rule.name)
            .with_context(|| format!("failed to resolve syscall '{}'", rule.name))?;
        let action = match rule.action {
            RuleAction::Notify => ScmpAction::Notify,
            RuleAction::Errno(errno) => ScmpAction::Errno(errno),
        };
        filter
            .add_rule(action, syscall)
            .with_context(|| format!("failed to add seccomp rule for '{}'", rule.name))?;
    }

    Ok(filter)
}

/// Verifies that the runtime `libseccomp` API can create user notifications.
///
/// User notification support requires both a recent enough library and API
/// level. Checking this up front gives a clear error before the child is forked.
fn ensure_user_notify_supported() -> Result<()> {
    let supported = check_api(6, ScmpVersion::from((2, 5, 0)))
        .context("failed to determine libseccomp API/version support")?;

    if !supported {
        bail!("seccomp user notifications require libseccomp >= 2.5.0 and API level >= 6");
    }

    Ok(())
}

/// Installs the wrapper seccomp filter and returns its notification listener fd.
///
/// The caller must transfer ownership of this fd to the parent supervisor before
/// allowing the child to execute any syscall that can be notified.
pub(crate) fn install_filter() -> Result<RawFd> {
    // A process can only have one useful listener for this filter. Reinstalling
    // would make ownership and notification routing ambiguous, so fail fast.
    if FILTER_INSTALLED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        bail!("seccomp filter has already been installed in this process");
    }

    ensure_user_notify_supported()?;

    let result = (|| {
        let filter = build_filter()?;
        filter
            .load()
            .context("failed to install seccomp filter with libseccomp")?;

        let listener_fd = filter
            .get_notify_fd()
            .context("failed to obtain seccomp user notification file descriptor")?;

        // Keep the loaded filter context alive for process lifetime so the
        // notification FD remains valid for the supervisor path.
        let _leaked_filter = Box::leak(Box::new(filter));
        Ok(listener_fd)
    })();

    if result.is_err() {
        FILTER_INSTALLED.store(false, Ordering::Relaxed);
    }

    result
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use super::{build_filter, syscall_rules, RuleAction};

    #[test]
    fn rules_match_expected_base_policy() {
        let rules = syscall_rules();

        // All deny rules must use Errno(EPERM).
        let deny_names: Vec<&str> = rules
            .iter()
            .filter(|r| r.action == RuleAction::Errno(libc::EPERM))
            .map(|r| r.name)
            .collect();
        assert_eq!(
            deny_names,
            vec![
                "ptrace",
                "process_vm_writev",
                "process_vm_readv",
                "pidfd_getfd",
                "userfaultfd",
                "unshare",
                "setns",
                "mount",
                "umount2",
                "mount_setattr",
                "fsopen",
                "fsmount",
                "move_mount",
            ]
        );

        // Exec-family rules must use Notify.
        let notify_names: Vec<&str> = rules
            .iter()
            .filter(|r| r.action == RuleAction::Notify)
            .map(|r| r.name)
            .collect();
        assert_eq!(notify_names, vec!["execve", "execveat"]);
    }

    #[test]
    fn generated_bpf_program_is_not_empty() {
        let filter = build_filter().expect("filter should build");

        let mut filter_file = tempfile::tempfile().expect("tempfile should be created");
        filter
            .export_bpf(&filter_file)
            .expect("filter should export BPF");
        filter_file.flush().expect("flush should succeed");
        filter_file
            .seek(SeekFrom::Start(0))
            .expect("seek should succeed");
        let mut bpf = Vec::new();
        filter_file
            .read_to_end(&mut bpf)
            .expect("read should succeed");

        assert!(!bpf.is_empty());
    }
}
