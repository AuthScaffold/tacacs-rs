use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};
use libseccomp::{check_api, ScmpAction, ScmpFilterContext, ScmpSyscall, ScmpVersion};

static FILTER_INSTALLED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Notify,
    Errno(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyscallRule {
    name: &'static str,
    action: RuleAction,
}

fn syscall_rules(intercept_fork: bool) -> Vec<SyscallRule> {
    let mut rules = vec![
        SyscallRule {
            name: "ptrace",
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
    ];

    if intercept_fork {
        rules.extend([
            SyscallRule {
                name: "clone",
                action: RuleAction::Notify,
            },
            SyscallRule {
                name: "fork",
                action: RuleAction::Notify,
            },
            SyscallRule {
                name: "vfork",
                action: RuleAction::Notify,
            },
            SyscallRule {
                name: "clone3",
                action: RuleAction::Notify,
            },
        ]);
    }

    rules
}

fn build_filter(intercept_fork: bool) -> Result<ScmpFilterContext> {
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow)
        .context("failed to create libseccomp filter context")?;

    filter
        .set_ctl_nnp(true)
        .context("failed to enable no_new_privs on seccomp filter")?;

    for rule in syscall_rules(intercept_fork) {
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

fn ensure_user_notify_supported() -> Result<()> {
    let supported = check_api(6, ScmpVersion::from((2, 5, 0)))
        .context("failed to determine libseccomp API/version support")?;

    if !supported {
        bail!("seccomp user notifications require libseccomp >= 2.5.0 and API level >= 6");
    }

    Ok(())
}

pub(crate) fn install_filter(intercept_fork: bool) -> Result<RawFd> {
    if FILTER_INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        bail!("seccomp filter has already been installed in this process");
    }

    ensure_user_notify_supported()?;

    let result = (|| {
        let filter = build_filter(intercept_fork)?;
        filter
            .load()
            .context("failed to install seccomp filter with libseccomp")?;

        let listener_fd = filter
            .get_notify_fd()
            .context("failed to obtain seccomp user notification file descriptor")?;

        let _leaked_filter = Box::leak(Box::new(filter));
        Ok(listener_fd)
    })();

    if result.is_err() {
        FILTER_INSTALLED.store(false, Ordering::SeqCst);
    }

    result
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};

    use super::{build_filter, syscall_rules, RuleAction, SyscallRule};

    #[test]
    fn rules_match_expected_base_policy() {
        assert_eq!(
            syscall_rules(false),
            vec![
                SyscallRule {
                    name: "ptrace",
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
        );
    }

    #[test]
    fn rules_include_fork_family_when_requested() {
        let rules = syscall_rules(true);
        assert!(rules.iter().any(|rule| rule.name == "clone"));
        assert!(rules.iter().any(|rule| rule.name == "fork"));
        assert!(rules.iter().any(|rule| rule.name == "vfork"));
        assert!(rules.iter().any(|rule| rule.name == "clone3"));
    }

    #[test]
    fn generated_bpf_program_changes_when_fork_interception_is_enabled() {
        let baseline_filter = build_filter(false).expect("baseline filter should build");
        let with_fork_filter = build_filter(true).expect("fork-intercept filter should build");

        let mut baseline_file = tempfile::tempfile().expect("tempfile should be created");
        baseline_filter
            .export_bpf(&baseline_file)
            .expect("baseline filter should export BPF");
        baseline_file
            .seek(SeekFrom::Start(0))
            .expect("seek should succeed");
        let mut baseline = Vec::new();
        baseline_file
            .read_to_end(&mut baseline)
            .expect("read should succeed");

        let mut with_fork_file = tempfile::tempfile().expect("tempfile should be created");
        with_fork_filter
            .export_bpf(&with_fork_file)
            .expect("fork-intercept filter should export BPF");
        with_fork_file
            .seek(SeekFrom::Start(0))
            .expect("seek should succeed");
        let mut with_fork = Vec::new();
        with_fork_file
            .read_to_end(&mut with_fork)
            .expect("read should succeed");

        assert!(!baseline.is_empty());
        assert!(with_fork.len() > baseline.len());
    }
}
