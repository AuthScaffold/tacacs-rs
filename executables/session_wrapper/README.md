# session-wrapper

`session-wrapper` is a Linux `x86_64` proof-of-concept login/session wrapper for TACACS+ command authorization. It starts a command under a seccomp user-notification filter. The parent wrapper process observes every `execve` crossing. It then decides, in real time, whether to allow or deny the command.

## Platform support

The workspace builds the wrapper only for Linux GNU `x86_64`. Other targets are not supported.

## What it does today

The wrapper:

1. Parses login/session context from CLI arguments.
2. Optionally loads an exec allowlist (one path per line, with built-in defaults always active).
3. Forks a child process.
4. Installs a seccomp user-notification filter in the child (notify on `execve`/`execveat`).
5. Sends the seccomp notification listener fd from child to parent over a Unix socketpair.
6. Connects to the TACACS+ IPC agent and starts the supervisor in the parent.
7. Releases the child once the supervisor is ready.
8. Drops the child to the requested UID/GID and execs `COMMAND [ARGS]...`.
9. For each intercepted exec:
   - Compares the exec path with the **allowlist**. If the path matches, it responds CONTINUE immediately.
   - Otherwise, sends a TACACS+ **accounting** record to the agent and interprets the response status as allow/deny.
   - On IPC failure, applies the configured `--fail-policy` (closed = deny, open = allow).
10. Keeps supervising until the initial child **and all subreaped descendants** exit.

The kernel inherits the seccomp filter across `fork`/`clone` calls and preserves it across `exec`. As a result, every nested shell, subshell, background job, and shell script in the wrapped session sends notifications to the same supervisor. The wrapper does not reinstall the filter.

## Module architecture

| Module | Responsibility |
|--------|---------------|
| `cli` | CLI argument parsing (clap) |
| `process` | Fork/exec lifecycle, seccomp fd hand-off, child subreaper |
| `seccomp` | BPF filter construction via `libseccomp-rs` |
| `allowlist` | Fast-path allow set loaded from file + built-in defaults |
| `process_reader` | Read exec args from `/proc/[pid]/mem` via `pread` |
| `supervisor` | Notification loop, IPC authorization calls, kernel responses |

## Why the process lifecycle is structured this way

The child installs seccomp before its first shell exec. Once installed, `execve` blocks in the kernel until the notification listener responds. The parent therefore must receive the notification fd and start a supervisor **before** releasing the child. A ready byte over the control socket provides that synchronization.

The control socket also lets the child report setup failures after fork. Without it, failures during privilege drop or exec look like a generic child exit.

The parent marks itself as a child subreaper. The kernel then reparents descendants that outlive the initial shell back to the wrapper. This keeps the notification fd alive until the whole process tree exits.

## Allowlist

On startup the supervisor loads an in-memory `HashSet` of executable paths. It always allows these paths to run without an IPC round-trip. The set always includes built-in defaults for shell infrastructure, such as `/bin/bash`, `/bin/sh`, `/usr/bin/env`, and `/usr/bin/id`. An optional configuration file can add more paths:

```
# One absolute path per line; # comments and blank lines are ignored
/usr/local/bin/my-tool
/opt/vendor/status
```

Pass the file with `--allowlist /path/to/file`.

## Reading exec arguments

When a notification arrives, the supervisor reads the executable path and argv
from the target process's virtual memory through `/proc/[pid]/mem` and `pread(2)`.
The kernel holds the notifying thread at the syscall boundary. Sibling threads in
the same process can still modify that memory before the kernel resumes the
syscall. The supervisor calls `check_notification_valid()` before and during the
read. This call makes sure that the notification is still pending, for example
because the process was not killed mid-read. It does not prove that the argv memory is unchanged.

## Seccomp policy

The policy is intentionally narrow — not a general sandbox:

| Syscall family | Action | Purpose |
|----------------|--------|---------|
| `execve`, `execveat` | Notify parent | Command execution authorization boundary |
| `ptrace` | `EPERM` | Prevent ptrace tampering |
| Everything else | Allow | Keep normal shell behavior working |

## CLI shape

Minimal local smoke-test invocation:

```bash
cargo build -p session-wrapper

target/debug/session-wrapper \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  -- /bin/bash
```

Useful options:

| Option | Meaning |
|--------|---------|
| `--user <NAME>` | Target username for TACACS+ accounting context |
| `--user-uid <UID>` | Target UID |
| `--user-gid <GID>` | Target primary GID |
| `--service-endpoint <PATH_OR_ADDR>` | TACACS+ IPC endpoint (default `/run/tacacs/tacacs.sock`) |
| `--fail-policy <closed\|open>` | What to do when the IPC agent is unreachable |
| `--allowlist <FILE>` | Additional exec allowlist file |
| `--port`, `--rem-addr` | TACACS+ context fields, typically from SSH environment |
| `COMMAND [ARGS]...` | Program and arguments execed in the child after privilege drop |

## Demo scripts

Runnable demos live in `demo/`:

```bash
executables/session_wrapper/demo/allow-all-basic.sh
executables/session_wrapper/demo/allow-all-descendants.sh
executables/session_wrapper/demo/allow-all-interactive-bash.sh
```

The basic and descendant demos are non-interactive and suitable for manual smoke testing. The interactive demo starts a wrapped Bash shell. All execs in that shell, including nested shells, subshells, and scripts, hit the supervisor.

## Validation

On Linux `x86_64`:

```bash
cargo clippy -p session-wrapper --all-targets -- -D warnings
cargo test -p session-wrapper
```

See [Session Wrapper Smoke and Integration Testing](../../docs/session-wrapper-testing.md) for detailed smoke tests and expected results. For SSH integration (`ForceCommand`, login-shell pattern, SSH environment-variable mapping), configuration examples, security considerations, and troubleshooting, see the [Session Wrapper Deployment Guide](../../docs/session-wrapper.md).

## Future work

1. After the agent implements a proper TACACS+ command-authorization RPC (`TAC_PLUS_AUTHOR`), replace the accounting-as-authorization proxy with it.
2. Add integration tests that exercise nested bash, `bash -c`, shell scripts, subshells, and background commands against a live TACACS+ test server.
3. Promote the non-interactive smoke demos into CI.
