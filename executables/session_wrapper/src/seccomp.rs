use std::mem::offset_of;
use std::os::fd::RawFd;

use anyhow::{Context, Result};

const X86_64_NR_CLONE: u32 = 56;
const X86_64_NR_FORK: u32 = 57;
const X86_64_NR_VFORK: u32 = 58;
const X86_64_NR_EXECVE: u32 = 59;
const X86_64_NR_PTRACE: u32 = 101;
const X86_64_NR_EXECVEAT: u32 = 322;
const X86_64_NR_CLONE3: u32 = 435;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const BPF_LD_NR: libc::c_ushort = 0x20;
const BPF_JEQ_K: libc::c_ushort = 0x15;
const BPF_RET_K: libc::c_ushort = 0x06;

fn syscall_nr_offset() -> u32 {
    u32::try_from(offset_of!(libc::seccomp_data, nr))
        .expect("seccomp_data.nr offset must fit in 32-bit cBPF k field")
}

fn stmt(code: libc::c_ushort, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump_eq(syscall_nr: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JEQ_K,
        jt: 0,
        jf: 1,
        k: syscall_nr,
    }
}

fn ret(action: u32) -> libc::sock_filter {
    stmt(BPF_RET_K, action)
}

pub(crate) fn build_filter_program(intercept_fork: bool) -> Vec<libc::sock_filter> {
    let mut filters = vec![stmt(BPF_LD_NR, syscall_nr_offset())];

    filters.extend([
        jump_eq(X86_64_NR_PTRACE),
        ret(SECCOMP_RET_ERRNO | libc::EPERM as u32),
        jump_eq(X86_64_NR_EXECVE),
        ret(SECCOMP_RET_USER_NOTIF),
        jump_eq(X86_64_NR_EXECVEAT),
        ret(SECCOMP_RET_USER_NOTIF),
    ]);

    if intercept_fork {
        filters.extend([
            jump_eq(X86_64_NR_CLONE),
            ret(SECCOMP_RET_USER_NOTIF),
            jump_eq(X86_64_NR_FORK),
            ret(SECCOMP_RET_USER_NOTIF),
            jump_eq(X86_64_NR_VFORK),
            ret(SECCOMP_RET_USER_NOTIF),
            jump_eq(X86_64_NR_CLONE3),
            ret(SECCOMP_RET_USER_NOTIF),
        ]);
    }

    filters.push(ret(SECCOMP_RET_ALLOW));
    filters
}

#[allow(unsafe_code)]
pub(crate) fn install_filter(intercept_fork: bool) -> Result<RawFd> {
    let mut filters = build_filter_program(intercept_fork);
    let program = libc::sock_fprog {
        len: filters
            .len()
            .try_into()
            .context("seccomp filter instruction count exceeds u16")?,
        filter: filters.as_mut_ptr(),
    };

    // SAFETY: Calling into libc with valid primitive arguments.
    let no_new_privs_result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privs_result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set PR_SET_NO_NEW_PRIVS before seccomp");
    }

    // SAFETY: `program` points to valid in-scope sock_fprog and seccomp syscall arguments
    // follow the kernel ABI for SECCOMP_SET_MODE_FILTER.
    let listener_fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &raw const program,
        )
    };
    if listener_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to install seccomp filter with NEW_LISTENER");
    }

    RawFd::try_from(listener_fd).context("kernel returned invalid seccomp listener fd")
}

#[cfg(test)]
mod tests {
    use super::{
        build_filter_program, X86_64_NR_CLONE, X86_64_NR_CLONE3, X86_64_NR_EXECVE,
        X86_64_NR_EXECVEAT, X86_64_NR_FORK, X86_64_NR_PTRACE, X86_64_NR_VFORK,
    };

    const BPF_LD_NR: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_USER_NOTIF: u32 = 0x7fc0_0000;

    fn assert_instr(instr: libc::sock_filter, code: u16, jt: u8, jf: u8, k: u32) {
        assert_eq!(instr.code, code as libc::c_ushort);
        assert_eq!(instr.jt, jt);
        assert_eq!(instr.jf, jf);
        assert_eq!(instr.k, k);
    }

    #[test]
    fn builds_expected_filter_without_fork_interception() {
        let program = build_filter_program(false);
        assert_eq!(program.len(), 8);

        assert_instr(
            program[0],
            BPF_LD_NR,
            0,
            0,
            u32::try_from(std::mem::offset_of!(libc::seccomp_data, nr))
                .expect("seccomp_data.nr offset must fit u32"),
        );
        assert_instr(program[1], BPF_JEQ_K, 0, 1, X86_64_NR_PTRACE);
        assert_instr(program[2], BPF_RET_K, 0, 0, RET_ERRNO | libc::EPERM as u32);
        assert_instr(program[3], BPF_JEQ_K, 0, 1, X86_64_NR_EXECVE);
        assert_instr(program[4], BPF_RET_K, 0, 0, RET_USER_NOTIF);
        assert_instr(program[5], BPF_JEQ_K, 0, 1, X86_64_NR_EXECVEAT);
        assert_instr(program[6], BPF_RET_K, 0, 0, RET_USER_NOTIF);
        assert_instr(program[7], BPF_RET_K, 0, 0, RET_ALLOW);
    }

    #[test]
    fn builds_expected_filter_with_fork_interception() {
        let program = build_filter_program(true);
        assert_eq!(program.len(), 16);

        assert_instr(program[7], BPF_JEQ_K, 0, 1, X86_64_NR_CLONE);
        assert_instr(program[8], BPF_RET_K, 0, 0, RET_USER_NOTIF);
        assert_instr(program[9], BPF_JEQ_K, 0, 1, X86_64_NR_FORK);
        assert_instr(program[10], BPF_RET_K, 0, 0, RET_USER_NOTIF);
        assert_instr(program[11], BPF_JEQ_K, 0, 1, X86_64_NR_VFORK);
        assert_instr(program[12], BPF_RET_K, 0, 0, RET_USER_NOTIF);
        assert_instr(program[13], BPF_JEQ_K, 0, 1, X86_64_NR_CLONE3);
        assert_instr(program[14], BPF_RET_K, 0, 0, RET_USER_NOTIF);
        assert_instr(program[15], BPF_RET_K, 0, 0, RET_ALLOW);
    }
}
