# session-wrapper — SSH-driven TACACS+ command authorization

`session-wrapper` is a per-session login wrapper that mediates command execution
through TACACS+ authorization. It is launched once per SSH login (typically by
`sshd` via `ForceCommand`), forks the user's shell under a seccomp
user-notification filter, and asks the local `tacacsrs-agentd` daemon whether
each `execve` should be allowed.

For module-level architecture and the wrapper's process lifecycle, see the
crate-level [README](../executables/session_wrapper/README.md). For local smoke
and integration tests, see the
[testing guide](session-wrapper-testing.md). For deploying the static binary to
SONiC, see the [SONiC build guide](sonic-build-guide.md).

## Architecture

```text
┌─────────┐  PAM/login   ┌────────────────────┐    seccomp notif     ┌────────┐
│  sshd   │─────────────▶│  session-wrapper   │◀════════════════════▶│  bash  │
│         │  ForceCommand│   (supervisor in   │       fork+exec      │ (user  │
│         │              │      parent)       │─────────────────────▶│ shell) │
└─────────┘              └─────────┬──────────┘                      └────────┘
                                   │ gRPC over Unix socket
                                   ▼
                         ┌────────────────────┐    TACACS+ TCP/TLS   ┌────────┐
                         │  tacacsrs-agentd   │─────────────────────▶│ TACACS+│
                         │  (long-running)    │                      │ server │
                         └────────────────────┘                      └────────┘
```

Key properties:

- The supervisor lives in the **parent** process. The user's shell runs in the
  **child**, after privilege drop, with the seccomp filter already installed.
- The seccomp filter is **inherited across `fork`/`clone`** and **preserved
  across `exec`**, so nested shells, subshells, pipelines, background jobs, and
  shell scripts in the wrapped session all hit the same supervisor without any
  re-installation.
- The supervisor keeps processing notifications until the wrapped session is
  **drained** — that is, until the initial shell *and* every reparented
  descendant have exited. It does not stop when the first shell PID exits.

## SSH integration

`session-wrapper` is invoked by `sshd` after a successful authentication. There
are two supported integration modes; pick whichever fits your platform.

### Option 1: `sshd_config` `ForceCommand` (recommended)

Add a `Match` block to `/etc/ssh/sshd_config` so users in a designated group
are forced through the wrapper regardless of which command they request:

Because `ForceCommand` takes a single command string and does not expand all
the SSH environment we want, the cleanest pattern is to point it at a tiny
shim script:

```sshd_config
Match Group tacacs-authorized
    ForceCommand /usr/local/sbin/tacacs-forcecommand
```

```bash
#!/bin/sh
# /usr/local/sbin/tacacs-forcecommand
#
# Invoked by sshd as the matched user, with $USER, $SSH_TTY, $SSH_CONNECTION,
# and (for non-interactive sessions) $SSH_ORIGINAL_COMMAND already in the
# environment. We translate those into session-wrapper flags and exec.
exec /usr/local/bin/session-wrapper \
    --user "$USER" \
    --user-uid "$(id -u)" \
    --user-gid "$(id -g)" \
    --service-endpoint /run/tacacs/tacacs.sock \
    --fail-policy closed \
    --port "${SSH_TTY:-ssh}" \
    --rem-addr "${SSH_CONNECTION%% *}" \
    -- /bin/bash ${SSH_ORIGINAL_COMMAND:+-c "$SSH_ORIGINAL_COMMAND"}
```

The shim must be `0755` and owned by `root:root`. `sshd` runs `ForceCommand`
with `/bin/sh -c`, so any single command string works directly, but a shim is
easier to maintain than a long inline command.

#### Why `ForceCommand`?

`ForceCommand` runs *unconditionally* for matched logins, even when the SSH
client requests a specific command (`ssh user@host -- whoami`). The original
command is exposed to the forced command via the `SSH_ORIGINAL_COMMAND`
environment variable, but the wrapper's seccomp filter still mediates
everything the user shell tries to exec.

### Option 2: Login shell via `/etc/passwd` or NSS

For platforms where modifying `sshd_config` is impractical, set
`session-wrapper` as the user's login shell. There are two common patterns:

1. **Direct `/etc/passwd` entry** — set the shell field to a small wrapper
   script that exec's `session-wrapper` with the right arguments:

   ```
   tacuser:x:1100:100:TACACS user:/home/tacuser:/usr/local/sbin/tacacs-login
   ```

   ```bash
   #!/bin/sh
   # /usr/local/sbin/tacacs-login
   exec /usr/local/bin/session-wrapper \
       --user "$USER" \
       --user-uid "$(id -u)" \
       --user-gid "$(id -g)" \
       --service-endpoint /run/tacacs/tacacs.sock \
       --fail-policy closed \
       --port "${SSH_TTY:-login}" \
       --rem-addr "${SSH_CONNECTION%% *}" \
       -- /bin/bash -l "$@"
   ```

   The wrapper script must be listed in `/etc/shells` and have mode `0755`.

2. **NSS-provided shell** — when users come from `libnss-tacplus` or a similar
   NSS module, configure that module to return the wrapper script path as the
   shell field. The mechanics are NSS-module specific; the wrapper script
   itself is identical to the one above.

Compared to `ForceCommand`, the login-shell pattern relies on the user not
being able to bypass their shell (e.g. `ssh -t user@host /bin/bash` would skip
it). Use `ForceCommand` whenever possible.

### SSH environment variables

`sshd` exposes connection metadata as environment variables that map directly
to TACACS+ context fields:

| SSH variable        | Format                                  | Wrapper flag |
|---------------------|-----------------------------------------|--------------|
| `SSH_CONNECTION`    | `<client_ip> <client_port> <server_ip> <server_port>` | `--rem-addr` (first field) |
| `SSH_CLIENT`        | `<client_ip> <client_port> <server_port>` (legacy) | `--rem-addr` (first field) |
| `SSH_TTY`           | `/dev/pts/N` when a tty is allocated    | `--port`     |
| `SSH_ORIGINAL_COMMAND` | command requested under `ForceCommand` | (logged via accounting) |

Recommended extraction:

```bash
REM_ADDR="${SSH_CONNECTION%% *}"   # first whitespace-delimited field
PORT="${SSH_TTY:-ssh}"             # fall back to "ssh" for non-tty sessions
```

These should be passed to `--rem-addr` and `--port` in your `ForceCommand` or
login-shell wrapper.

## CLI reference

```text
session-wrapper [OPTIONS] -- COMMAND [ARGS]...
```

| Option                          | Default              | Purpose |
|---------------------------------|----------------------|---------|
| `--user <NAME>`                 | *(required)*         | Target username for TACACS+ accounting context |
| `--user-uid <UID>`              | *(required)*         | UID to drop to before exec |
| `--user-gid <GID>`              | *(required)*         | Primary GID to drop to before exec |
| `--service-endpoint <PATH>`     | `/run/tacacs/tacacs.sock`   | Unix socket (or `host:port`) for `tacacsrs-agentd` IPC |
| `--fail-policy <closed\|open>`  | `closed`             | What to do when IPC is unreachable |
| `--authorization-timeout-ms <N>`| `5000`               | Per-request authorization timeout (ms) |
| `--privilege-level <0..=15>`    | `1`                  | Current TACACS+ privilege level |
| `--allowlist <FILE>`            | *(none)*             | Extra exec allowlist file (built-ins always active) |
| `--port <STR>`                  | *(none)*             | TACACS+ port context, typically `$SSH_TTY` |
| `--rem-addr <STR>`              | *(none)*             | TACACS+ remote address context, typically the first field of `$SSH_CONNECTION` |
| `-v` / `-vv` / `-vvv` / `-vvvv` | `0`                  | Increase log verbosity |
| `COMMAND [ARGS]...`             | *(required)*         | Program execed in the child after privilege drop |

Run `session-wrapper --help` for the authoritative list (it is generated from
`clap` annotations and tracks the source).

## Configuration examples

### Fail-closed (production default)

Deny the session if the local agent or the upstream TACACS+ server is
unreachable. This is the safe default for managed network devices.

```bash
session-wrapper \
    --user alice --user-uid 1100 --user-gid 100 \
    --service-endpoint /run/tacacs/tacacs.sock \
    --fail-policy closed \
    --authorization-timeout-ms 3000 \
    -- /bin/bash
```

### Fail-open (lab / bring-up only)

Allow the session if authorization cannot be reached. Use only during
bring-up, lab testing, or for break-glass roles where lockout is worse than
unaudited access.

```bash
session-wrapper \
    --user alice --user-uid 1100 --user-gid 100 \
    --fail-policy open \
    -- /bin/bash
```

### Allowlist for high-frequency built-ins

Authorization round-trips on every `execve` are expensive for shells that
fork frequently (prompt rendering, completion, pipelines). The wrapper ships a
built-in allowlist for shell infrastructure (`/bin/bash`, `/bin/sh`,
`/usr/bin/env`, `/usr/bin/id`, …); add site-specific tools by file:

```text
# /etc/session-wrapper.allow
# One absolute path per line; '#' comments and blank lines are ignored.
/usr/local/bin/show-version
/usr/local/bin/show-interfaces
/opt/vendor/diag
```

```bash
session-wrapper \
    --user alice --user-uid 1100 --user-gid 100 \
    --allowlist /etc/session-wrapper.allow \
    -- /bin/bash
```

Allowlist entries match the resolved exec path. They bypass the IPC round-trip
entirely, so they are not visible in TACACS+ accounting — keep the list to
genuinely uninteresting helpers.

## Security considerations

### TOCTOU (time-of-check / time-of-use)

When a notification fires, the supervisor reads the target process's argv
from `/proc/[pid]/mem` while the notifying thread is held at the syscall
boundary. That does **not** make the process address space immutable: another
thread in the same process can still rewrite the exec path after the supervisor
reads it and before the kernel resumes the syscall. `check_notification_valid()`
only confirms that the notification is still pending, for example because the
target process was not killed or reaped mid-read; it does not prove that argv
memory is unchanged.

This TOCTOU window is inherent to seccomp user notifications and cannot be
completely eliminated inside the seccomp authorization path. Practical mitigations
can reduce exploitability, such as denying `userfaultfd` and `process_vm_writev`,
but complete protection requires a kernel-enforced execution boundary such as
Landlock, AppArmor, SELinux, or an equivalent LSM policy.

### `ptrace` is blocked

`ptrace(2)` is forced to fail with `EPERM` inside the wrapped session. This
prevents a debugger inside the session from rewriting another process's argv
between notify and exec, attaching to the supervisor, or detaching the
seccomp filter. Tools that legitimately need `ptrace` (`gdb`, `strace`) will
not work inside the wrapped shell — that is intentional.

### Privilege drop

The wrapper expects to be started as `root` (so it can `setgid`/`setuid` to
the target user) and drops to `--user-uid` / `--user-gid` in the **child**
before `execve`. The supervisor parent retains its original privileges only
long enough to receive the seccomp listener fd, then services notifications
without any need to be root for the wrapped session itself.

If the wrapper is started as a non-root user that already matches `--user-uid`
the drop is a no-op; this is the expected configuration when launched from a
PAM session that already changed identity.

### Descendant coverage

The seccomp filter is installed once, in the child, before its first
`execve`. It is **inherited across `fork`/`clone` and preserved across
`exec`**, so:

- Subshells, pipelines, and background jobs are mediated.
- Nested `bash`, `sh -c "…"`, and shell scripts are mediated.
- A long-lived background job that outlives the user's interactive shell is
  still mediated for its remaining `execve`s.

The parent registers itself as a **child subreaper** (`prctl(PR_SET_CHILD_SUBREAPER)`),
so descendants whose original parent exits are reparented back to the
wrapper. The supervisor keeps the notification fd open and continues to
service notifications until the entire subtree has been reaped — not just
until the initial shell PID exits.

### IPC trust boundary

The wrapper only authenticates the IPC endpoint via filesystem permissions
on the Unix socket (or network ACLs for TCP endpoints). The
`tacacsrs-agentd` socket should be mode `0660` and owned by a group that
includes the wrapper's UID. Do not point `--service-endpoint` at a
user-writable path.

## Troubleshooting

### "child setup failed: …" on the first command

The child reports setup errors back to the parent over the control socket
before exec. Look at the message text:

- **`execv …: No such file or directory`** — the wrapped command does not
  exist on the target. Check the absolute path passed after `--`.
- **`setgid` / `setuid` failure** — the wrapper was not started with enough
  privilege to drop to the requested UID/GID. Run as root, or have PAM hand
  the wrapper an already-correct identity and pass matching `--user-uid` /
  `--user-gid`.
- **`prctl(PR_SET_NO_NEW_PRIVS)` failure** — the kernel is older than 3.5 or
  the process already has restrictive flags. The wrapper requires
  `NO_NEW_PRIVS` to install an unprivileged seccomp filter.

### Session hangs immediately after login

The supervisor likely failed to start. Possible causes:

- `tacacsrs-agentd` is not running. Confirm the socket exists
  (`ls -l /run/tacacs/tacacs.sock`) and the daemon is listening.
- The wrapper does not have permission to connect to the socket. Check the
  socket's mode and the wrapped user's group membership.
- A `--fail-policy closed` deployment combined with an unreachable agent will
  hang only briefly — then the session will be denied with a clear error in
  the wrapper's log. If you see an indefinite hang instead, increase
  verbosity with `-vv` and re-run.

### Session does not exit after the user logs out

The wrapper waits for the **entire** wrapped subtree, not just the
interactive shell. Common causes:

- A background job (`some-tool &` or `nohup …`) is still running and still
  inherits the seccomp filter. Send SIGTERM/SIGKILL to that PID, or have the
  user use `disown -h` and detach via `nohup … </dev/null >/dev/null 2>&1 &`
  *before* logging out so the descendant is fully detached.
- A shell function or trap kept a subshell alive. Inspect
  `ps --ppid <wrapper_pid>` and the wider subtree (`pstree -p <wrapper_pid>`).
- A daemonized process forgot to `setsid` and is still parented to the
  subreaper. Either fix the daemon or kill the orphan.

This is by design: stopping supervision while a descendant is still alive
would create an authorization gap. If you need to forcibly tear down the
wrapped session, signal the wrapper PID — it will propagate signals and reap
descendants.

### Built-in commands cause unexpected denies

Built-in shell commands (`cd`, `echo` when implemented in the shell, `if`,
`for`, …) do not call `execve` and are never seen by the wrapper. If
`/bin/echo` is being denied while `echo` works, the user is invoking the
external binary explicitly — add it to the allowlist or to TACACS+ command
authorization rules.

### Authorization round-trips are slow

Every `execve` outside the allowlist costs a TACACS+ round-trip. For
prompt-heavy interactive shells this is visible as latency on each command.
Mitigations, in order of preference:

1. Add high-frequency, harmless binaries to `--allowlist`.
2. Tune `--authorization-timeout-ms` down so failed servers are detected
   faster (only useful with multiple agentd upstreams configured).
3. Ensure `tacacsrs-agentd` is configured with multiple upstream servers so
   failover does not stall.

### Verifying with the demo scripts

The wrapper ships allow-all demos in `executables/session_wrapper/demo/` that
exercise the lifecycle without needing TACACS+ infrastructure:

```bash
executables/session_wrapper/demo/allow-all-basic.sh
executables/session_wrapper/demo/allow-all-descendants.sh
executables/session_wrapper/demo/allow-all-interactive-bash.sh
```

If these demos pass but a real SSH login does not, the problem is in the SSH
integration (`ForceCommand` arguments, login shell wrapper, environment
variables) rather than in the wrapper itself.
