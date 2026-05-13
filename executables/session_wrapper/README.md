# session-wrapper

`session-wrapper` is a Linux `x86_64` proof-of-concept login/session wrapper for TACACS+ command authorization. It starts a command under a seccomp user-notification filter so the parent wrapper process can observe every `execve` crossing and decide — in real time — whether to allow or deny command execution.

## Platform support

The real wrapper is compiled only on Linux `x86_64`, where seccomp user notifications and the current `libseccomp-rs` integration are available. Other platforms compile a noop entrypoint so the workspace still builds on macOS and Windows.

## What it does today

The wrapper:

1. Parses login/session context from CLI arguments.
2. Optionally loads an exec allowlist (one path per line; built-in defaults always active).
3. Forks a child process.
4. Installs a seccomp user-notification filter in the child (notify on `execve`/`execveat`).
5. Sends the seccomp notification listener fd from child to parent over a Unix socketpair.
6. Connects to the TACACS+ IPC agent and starts the supervisor in the parent.
7. Releases the child once the supervisor is ready.
8. Drops the child to the requested UID/GID and execs `COMMAND [ARGS]...`.
9. For each intercepted exec:
   - Checks the exec path against the **allowlist** — if matched, responds CONTINUE immediately.
   - Otherwise, sends a TACACS+ **accounting** record to the agent and interprets the response status as allow/deny.
   - On IPC failure, applies the configured `--fail-policy` (closed = deny, open = allow).
10. Keeps supervising until the initial child **and all subreaped descendants** exit.

The seccomp filter is inherited across `fork`/`clone` and preserved across `exec`, so every nested shell, subshell, background job, and shell script in the wrapped session sends notifications through the same supervisor without any re-installation.

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

The control socket also lets the child report setup failures after fork — without this, failures during privilege drop or exec would look like a generic child exit.

The parent marks itself as a child subreaper so descendants that outlive the initial shell are reparented back to the wrapper, keeping the notification fd alive until the whole process tree exits.

## Allowlist

On startup the supervisor loads an in-memory `HashSet` of executable paths that are always allowed to run without an IPC round-trip. The set always includes built-in defaults for shell infrastructure (`/bin/bash`, `/bin/sh`, `/usr/bin/env`, `/usr/bin/id`, etc.). An optional config file can add more paths:

```
# One absolute path per line; # comments and blank lines are ignored
/usr/local/bin/my-tool
/opt/vendor/status
```

Pass the file with `--allowlist /path/to/file`.

## Reading exec arguments

When a notification arrives, the supervisor reads the executable path and argv from the target process's virtual memory via `/proc/[pid]/mem` and `pread(2)`. The process is frozen at the syscall boundary, so its memory is stable. `check_notification_valid()` is called before and during the read to detect if the process was killed mid-read (TOCTOU mitigation).

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
| `--service-endpoint <PATH_OR_ADDR>` | TACACS+ IPC endpoint (default `/run/tacacs.sock`) |
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

The basic and descendant demos are non-interactive and suitable for manual smoke testing. The interactive demo starts a wrapped Bash shell; all execs (including nested shells, subshells, and scripts) hit the supervisor.

## Validation

On Linux `x86_64`:

```bash
cargo clippy -p session-wrapper --all-targets -- -D warnings
cargo test -p session-wrapper
```

For musl validation, provide a musl-targeted static `libseccomp` and run:

```bash
export LIBSECCOMP_LIB_PATH=/path/to/libseccomp-musl/lib
export LIBSECCOMP_LINK_TYPE=static
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH=/path/to/libseccomp-musl/lib/pkgconfig

cargo clippy -p session-wrapper --target x86_64-unknown-linux-musl --all-targets -- -D warnings
cargo test -p session-wrapper --target x86_64-unknown-linux-musl
```

See [Session Wrapper Smoke and Integration Testing](../../docs/session-wrapper-testing.md) for detailed smoke tests and expected results. Native Alpine builds have a separate [Alpine Linux technical note](README.alpine.md). For SSH integration (`ForceCommand`, login-shell pattern, SSH environment-variable mapping), configuration examples, security considerations, and troubleshooting, see the [Session Wrapper Deployment Guide](../../docs/session-wrapper.md).

## Future work

1. Replace the accounting-as-authorization proxy with a proper TACACS+ command-authorization RPC (`TAC_PLUS_AUTHOR`) once it is implemented in the agent.
2. Add integration tests that exercise nested bash, `bash -c`, shell scripts, subshells, and background commands against a live TACACS+ test server.
3. Promote the non-interactive smoke demos into CI.
