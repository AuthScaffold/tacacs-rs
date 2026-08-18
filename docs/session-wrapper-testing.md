# Session Wrapper Smoke and Integration Testing

This document describes local tests that make sure that the Linux
`session-wrapper` path works as expected. The real process mediation backend
is Linux x86_64 only. Other platforms build the portable CLI, allowlist,
deny-message, and authorization decision logic over a mock PAL backend. This
backend returns an explicit unsupported-platform error instead of executing
or mediating commands.

For architecture, CLI shape, and current implementation scope, see the [session-wrapper README](../executables/session_wrapper/README.md).

## Current scope

These checks focus on process lifecycle, seccomp user notification wiring, and
child/descendant supervision. The smoke tests below use fail-open behavior or
the allow-all demo scripts. This lets them validate the Linux mediation path
without a running `tacacsrs-agentd` service or TACACS+ server. They do not
prove an end-to-end TACACS+ authorization policy.

The trailing `COMMAND [ARGS]...` is the process that the wrapper runs under
supervision. Smoke tests use small temporary scripts as the wrapped command.

## Demo scripts

Runnable allow-all demos live in `executables/session_wrapper/demo/`:

| Script | Purpose |
| ------ | ------- |
| `allow-all-basic.sh` | Builds `session-wrapper`, runs a short wrapped script, and makes sure that the wrapped process wrote a marker file |
| `allow-all-descendants.sh` | Runs a wrapped script that exits while a descendant continues |
| `allow-all-interactive-bash.sh` | Starts an interactive Bash session under the current allow-all supervisor for manual exploration |

Run them from anywhere inside a Linux x86_64 checkout:

```bash
executables/session_wrapper/demo/allow-all-basic.sh
executables/session_wrapper/demo/allow-all-descendants.sh
executables/session_wrapper/demo/allow-all-interactive-bash.sh
```

## Prerequisites

On Debian or Ubuntu, install the native Linux dependencies:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libseccomp-dev
```

## Compile-time integration checks

Run these checks on Linux GNU x86-64:

```bash
cargo clippy -p session-wrapper --all-targets -- -D warnings
cargo test -p session-wrapper
```

These tests cover CLI parsing, seccomp policy generation, file descriptor passing, child setup status reporting, and socket close handling.

They do not prove that the wrapper can run a real child process. Thus, also run the smoke tests that follow.

## Smoke test: child starts and exits

This test makes sure that the parent completes the full startup path. It
receives the notification fd, starts the temporary allow-all supervisor,
releases the child, handles the child's initial `execve`, and exits when the
child exits.

```bash
cargo build -p session-wrapper

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/exit-zero" <<'EOF'
#!/bin/sh
printf 'ok\n' > "$SESSION_WRAPPER_SMOKE_MARKER"
EOF
chmod +x "$tmp/exit-zero"

SESSION_WRAPPER_SMOKE_MARKER="$tmp/marker" \
timeout 10s target/debug/session-wrapper \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  --fail-policy open \
  -- "$tmp/exit-zero"

test "$(cat "$tmp/marker")" = "ok"
```

Expected result: the command exits successfully and the marker contains `ok`. A timeout usually means the supervisor is not responding to seccomp notifications or the child was not released.

## Smoke test: child setup failures are reported

This test makes sure that the child reports setup errors back to the parent instead of hanging or silently exiting.

```bash
cargo build -p session-wrapper

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if timeout 10s target/debug/session-wrapper \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  --fail-policy open \
  -- "$tmp/does-not-exist" 2>"$tmp/error"; then
  echo "expected session-wrapper to fail for a missing command" >&2
  exit 1
fi

grep -E 'child setup failed|execv' "$tmp/error"
```

Expected result: the command fails quickly and stderr includes the child setup or `execv` failure.

## Smoke test: descendant execution remains supervised

This test makes sure that seccomp inheritance and subreaper lifecycle tracking work. The initial child starts a background descendant and exits. The wrapper must stay alive until the descendant has run its own exec path and exited.

```bash
cargo build -p session-wrapper

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/descendant" <<'EOF'
#!/bin/sh
(
  sleep 0.2
  /bin/sh -c 'printf "descendant-ok\n" > "$SESSION_WRAPPER_DESCENDANT_MARKER"'
) &
exit 0
EOF
chmod +x "$tmp/descendant"

SESSION_WRAPPER_DESCENDANT_MARKER="$tmp/descendant-marker" \
timeout 10s target/debug/session-wrapper \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  --fail-policy open \
  -- "$tmp/descendant"

test "$(cat "$tmp/descendant-marker")" = "descendant-ok"
```

Expected result: the marker contains `descendant-ok`. A missing marker or timeout indicates the wrapper stopped supervising before descendants completed, or fork/exec notifications were not continued.

## Optional smoke test: privileged identity drop

When you need to make sure that the root-to-user path used by login integrations works, run this test. It requires `sudo`.

```bash
cargo build -p session-wrapper

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/identity" <<'EOF'
#!/bin/sh
printf '%s:%s\n' "$(id -u)" "$(id -g)" > "$SESSION_WRAPPER_IDENTITY_MARKER"
EOF
chmod +x "$tmp/identity"

target_user=$(id -un)
target_uid=$(id -u)
target_gid=$(id -g)

sudo env SESSION_WRAPPER_IDENTITY_MARKER="$tmp/identity-marker" \
  target/debug/session-wrapper \
  --user "$target_user" \
  --user-uid "$target_uid" \
  --user-gid "$target_gid" \
  --fail-policy open \
  -- "$tmp/identity"

test "$(cat "$tmp/identity-marker")" = "$target_uid:$target_gid"
```

Expected result: the marker contains the target user's UID and primary GID, not `0:0`.

## Automation candidates

These smoke tests are good candidates for a Linux-only integration test job once the wrapper behavior stabilizes:

| Check | Requires root | Purpose |
| ----- | ------------- | ------- |
| Compile-time integration checks | No | Covers Rust code, seccomp policy construction, and fd passing |
| Child starts and exits | No | Validate notification fd handoff, ready synchronization, and child exec |
| Missing shell failure | No | Validate child-to-parent setup error reporting |
| Descendant execution | No | Validate inherited seccomp coverage and subreaper lifecycle handling |
| Privileged identity drop | Yes | Validate login-style root-to-user execution |

When real IPC authorization is wired in, keep these smoke tests. Replace the allow-all assumption with a test IPC service that records each authorization request and responds with the desired decision.
