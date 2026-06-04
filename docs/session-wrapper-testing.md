# Session Wrapper Smoke and Integration Testing

This document describes local checks that verify the Linux `session-wrapper` path is operating as expected. The real process mediation backend is Linux x86_64 only. Other platforms build the portable CLI, allowlist, deny-message, and authorization decision logic over a mock PAL backend that returns an explicit unsupported-platform error instead of executing or mediating commands.

For architecture, CLI shape, and current implementation scope, see the [session-wrapper README](../executables/session_wrapper/README.md).

## Current scope

The session wrapper currently verifies process lifecycle and seccomp user notification wiring. TACACS+ authorization decisioning is intentionally stubbed as allow-all for now, so these smoke tests do not require a running `tacacsrs-agentd` service or TACACS+ server.

The trailing `COMMAND [ARGS]...` is the process that is executed under supervision. Smoke tests use small temporary scripts as the wrapped command.

## Demo scripts

Runnable allow-all demos live in `executables/session_wrapper/demo/`:

| Script | Purpose |
| ------ | ------- |
| `allow-all-basic.sh` | Builds `session-wrapper`, runs a short wrapped script, and verifies the wrapped process wrote a marker file |
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
sudo apt-get install -y build-essential gperf libseccomp-dev linux-libc-dev musl-tools
rustup target add x86_64-unknown-linux-musl
```

GNU builds can use the distribution `libseccomp-dev`. Musl builds require a musl-targeted static libseccomp. In CI this is built and cached by the shared Rust setup action. Locally, point Cargo at a musl libseccomp install before running musl checks:

```bash
export LIBSECCOMP_LIB_PATH=/path/to/libseccomp-musl/lib
export LIBSECCOMP_LINK_TYPE=static
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH=/path/to/libseccomp-musl/lib/pkgconfig
```

Native Alpine builds have one extra `libseccomp`/musl linking caveat. See the crate-local [Alpine Linux technical note](../executables/session_wrapper/README.alpine.md).

## Compile-time integration checks

On non-Linux development machines, run the portable checks first:

```bash
cargo check -p session-wrapper
cargo test -p session-wrapper
cargo clippy -p session-wrapper --all-targets -- -D warnings
```

These checks exercise the portable modules and the mock PAL backend. They do not
validate fork, seccomp, `/proc`, signal, or child-reaping behavior.

Run these on Linux x86_64:

```bash
cargo clippy -p session-wrapper --all-targets -- -D warnings
cargo test -p session-wrapper
```

Run these when validating the static musl path:

```bash
cargo clippy -p session-wrapper --target x86_64-unknown-linux-musl --all-targets -- -D warnings
cargo test -p session-wrapper --target x86_64-unknown-linux-musl
```

These tests validate CLI parsing, seccomp policy generation, file descriptor passing, child setup status reporting, and socket close handling. They do not prove that a real child process can execute under the wrapper, so run the smoke tests below as well.

## Smoke test: child starts and exits

This verifies the parent receives the notification fd, starts the temporary allow-all supervisor, releases the child, handles the child's initial `execve`, and exits when the child exits.

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

This verifies the child reports setup errors back to the parent instead of hanging or silently exiting.

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

This verifies seccomp inheritance and subreaper lifecycle tracking. The initial child starts a background descendant and exits; the wrapper should stay alive until the descendant has run its own exec path and exited.

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

Run this when you need to verify the root-to-user path used by login integrations. It requires `sudo`.

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
| Compile-time integration checks | No | Validate Rust code, seccomp policy construction, fd passing, and musl compatibility |
| Child starts and exits | No | Validate notification fd handoff, ready synchronization, and child exec |
| Missing shell failure | No | Validate child-to-parent setup error reporting |
| Descendant execution | No | Validate inherited seccomp coverage and subreaper lifecycle handling |
| Privileged identity drop | Yes | Validate login-style root-to-user execution |

When real IPC authorization is wired in, keep these smoke tests but replace the allow-all assumption with a test IPC service that records each authorization request and responds with the desired decision.
