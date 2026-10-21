# Direct Systemd Notification Evaluation

## Decision

Retain the daemon's bounded subprocess owner. Reject both evaluated direct APIs.
The predecessor is `680b6f3c8c813e6f3c803673975a4bd73208c433`.
The integration changes only this document. No production code, dependency, or policy changes enter integration.

The prototype used `refactor/general-prototypes/16-systemd-notifications` in `/home/ubuntu/tacacs-rs-16-systemd-notifications-prototype`.
The frozen prototype commit is [`3a759ba3cf9c2cf3654d5bf739e578eb2c4a14de`](https://github.com/AuthScaffold/tacacs-rs/commit/3a759ba3cf9c2cf3654d5bf739e578eb2c4a14de).
The remote branch `origin/refactor/general-prototypes/16-systemd-notifications` preserves this commit separately from integration.
The evaluation started at 08:12:16 UTC on 2026-10-20.
The first valid pressure result established rejection before 08:15:56 UTC, less than four minutes after the start.
Later checks characterized the unchanged owner and the final probe.
The final focused checks completed at 08:19:30 UTC.
Both times are within the 45-minute budget.
No third API, adapter, or replacement implementation followed the rejection.

## Package Facts

| API | License | Declared MSRV | Normal dependencies |
| --- | --- | --- | --- |
| `sd-notify 0.5.0`, `sd_notify::notify` | `MIT OR Apache-2.0` | Rust 1.82 | `libc ^0.2`. Optional `sendfd ^0.4` stays disabled because the `fdstore` feature is off. |
| `libsystemd 0.7.2`, `libsystemd::daemon::notify` | `MIT/Apache-2.0` | Rust 1.69 | `hmac`, `libc`, `log`, `nix`, `nom`, `once_cell`, `serde`, `sha2`, `thiserror`, `uuid`. |

The version-specific registry metadata and downloaded manifests agree.
The archive SHA-256 values match the registry checksums:

```text
3e4ef7359e694bfaf1dd27a30f9d760b54c00dfae9f19bd0c05a39bc9128fe76  sd-notify-0.5.0.crate
19c97a761fc86953c5b885422b22c891dbf5bcb9dcc99d0110d6ce4c052759f0  libsystemd-0.7.2.crate
```

The isolated lockfile contains 45 registry packages, including target-specific dependencies.
The Linux normal and build dependency closure contains two packages for `sd-notify` and 32 for `libsystemd`, including each candidate.
These are prototype resolution counts, not proposed additions to the workspace lockfile.
Neither Linux closure requires a systemd development package, the libsystemd C library, or `pkg-config` discovery.
The native probe links libc and libgcc, but not libsystemd.
No native package or experimental tool installation occurred.

The isolated `sd-notify` dependency passes a Rust 1.88 check.
The combined lockfile fails that check because selected transitive dependency `uuid 1.28.0` requires Rust 1.89.
This result does not contradict the declared MSRV of `libsystemd` itself.
No pin repair followed the required socket-capability failures.
The workspace MSRV and lockfile remain unchanged.

Sources:
[sd-notify metadata](https://crates.io/api/v1/crates/sd-notify/0.5.0),
[sd-notify dependencies](https://crates.io/api/v1/crates/sd-notify/0.5.0/dependencies),
[sd-notify source](https://docs.rs/sd-notify/0.5.0/src/sd_notify/lib.rs.html),
[libsystemd metadata](https://crates.io/api/v1/crates/libsystemd/0.7.2),
[libsystemd dependencies](https://crates.io/api/v1/crates/libsystemd/0.7.2/dependencies),
[libsystemd source](https://docs.rs/libsystemd/0.7.2/src/libsystemd/daemon.rs.html).

## Discriminating Results

The probe binds only private pathname sockets and unique Linux abstract sockets.
Each child receives an explicit private `NOTIFY_SOCKET`.
The harness never changes its own environment or contacts a service manager.
Receivers use `SO_PASSCRED` and compare `SCM_CREDENTIALS` with each owned child.

| API and address | Normal send | Receiver does not drain |
| --- | --- | --- |
| `sd-notify`, pathname | `READY=1` arrives with the child PID, UID, and GID. | Blocks until the harness kills and reaps its owned child. |
| `sd-notify`, abstract (`@name`) | Returns exit 1: `No such file or directory (os error 2)`. | Not run after the normal address failure. |
| `libsystemd`, pathname | `READY=1` arrives with the child PID, UID, and GID. | Blocks until the harness kills and reaps its owned child. |
| `libsystemd`, abstract (`@name`) | `READY=1` arrives with the child PID, UID, and GID. | Blocks until the harness kills and reaps its owned child. |

The pressure fixture keeps all filler sockets open.
A fresh nonblocking sender receives `EAGAIN` before each candidate starts.
This step distinguishes receiver pressure from a full sender buffer.
In each final pressure case, two filler sockets queue 513 datagrams.
The third filler socket is the fresh sender that receives `EAGAIN`.
On this host, `net.unix.max_dgram_qlen` is 512, and the kernel accepts one datagram past that value.
No receiver read occurs before child termination.

Each blocked child prints its entry marker and remains in kernel wait channel `unix_wait_for_peer`.
The harness imposes a 750ms process deadline.
The three observed waits are 0.753s, 0.752s, and 0.752s, including termination and reaping.
Each child exits with signal 9, reported as `-9`.
All private sockets close and all fixture paths disappear.
The characterization exits 0 for seven expected results, with no harness skips.
That exit means the failures reproduced. It does not mean acceptance passed.

The published implementations explain these results.
`sd-notify` connects a private blocking `UnixDatagram` to the supplied path, then calls `send`.
It does not translate `@name` to an abstract address.
`libsystemd` supports abstract addresses but calls `sendmsg` with empty flags on a private blocking socket.
Neither notification API exposes its socket, a nonblocking setting, or a send deadline.

## Ownership And Deletion Assessment

The current [host adapter](../executables/tacacsrs_agentd/src/host_integration.rs) remains daemon-owned.
It selects none, auto, or strict systemd mode and delegates delivery to `systemd-notify --pid=parent`.
Auto mode logs a warning and retries an owed one-shot flag after a one-second backoff.
Strict errors remain fatal.
The adapter marks ready and stopping flags as delivered only after command success.
Repeated health snapshots do not resend a successfully delivered one-shot flag.
Status text remains sanitized.

The [supervisor](../executables/tacacsrs_agentd/src/supervision.rs) captures one cleanup deadline.
Its task abort drops the asynchronous child owner, whose `kill_on_drop(true)` terminates a stalled helper.
This bound applies to teardown, not to each notification during normal service.
The native regression confirms that a stalled helper does not hold shutdown open.

An in-process blocking send does not preserve this cancellation contract.
`spawn_blocking` cannot cancel an active native call and does not establish bounded runtime shutdown.
A detached thread lets the runtime stop, but no owner can end its blocked call before process exit.
The current owner terminates the stalled helper at the teardown deadline.

| Production area | Potential deletion with an acceptable API | Actual integration result |
| --- | --- | --- |
| `ProcessSystemdCommand::is_available` and strict helper check | PATH traversal, executable checks, helper-only diagnostics | Retained unchanged |
| `ProcessSystemdCommand::execute` | Command execution, exit-status handling, child ownership | Retained unchanged |
| Helper imports and `--pid=parent` argument | Subprocess-specific plumbing | Retained unchanged |
| `HostIntegration::select`, retry loop, one-shot flags, status mapping | None. These remain daemon responsibilities. | Retained unchanged |
| Supervision, health, cancellation, cleanup deadline | None. Their contracts must remain. | Retained unchanged |

The current module contains 235 production lines before its test module.
Adopted production deletions: zero. Added production lines: zero.
A library call in another child process retains the machinery that this evaluation seeks to remove.
A custom socket implementation bypasses the candidate APIs instead of adopting them.
Neither alternative provides an acceptable deletion map.

## Replay And Checks

If the prototype directory is missing, run these commands from an existing repository checkout:

```bash
git fetch origin refs/heads/refactor/general-prototypes/16-systemd-notifications
git worktree add --detach "$HOME/tacacs-rs-16-systemd-notifications-prototype" \
  3a759ba3cf9c2cf3654d5bf739e578eb2c4a14de
```

Run these commands in the preserved prototype worktree:

```bash
source /etc/profile.d/tacacs-rs.sh
cd "$HOME/tacacs-rs-16-systemd-notifications-prototype"
export CARGO_TARGET_DIR="$HOME/.cache/tacacs-rs-16-systemd-notifications-prototype"
export CARGO_BUILD_JOBS=4
cargo +stable build --quiet --locked --manifest-path experiments/systemd-notifications/Cargo.toml
PYTHONDONTWRITEBYTECODE=1 python3 experiments/systemd-notifications/probe.py \
  --binary "$CARGO_TARGET_DIR/debug/systemd-notification-probe"
cargo +1.88.0 check --quiet --locked --manifest-path experiments/systemd-notifications/Cargo.toml -p sd-notify
cargo +1.88.0 check --quiet --locked --manifest-path experiments/systemd-notifications/Cargo.toml
```

The build, characterization, and selected `sd-notify` MSRV check exit 0.
The final combined MSRV command exits 101 for the recorded `uuid` requirement.
The initial probe build used an obsolete `sd-notify` call signature and exited 101 before any socket call.
The corrected build passes.
An initial pressure fixture released filler sockets too early and failed its own assertions.
Only the corrected receiver-saturation results support this decision.

Run these unchanged-owner regressions in the same shell. They exit 0:

```bash
env -u NOTIFY_SOCKET cargo +stable test --quiet -p tacacsrs-agentd \
  --bin tacacsrs-agentd --locked -- host_integration::
env -u NOTIFY_SOCKET cargo +stable test --quiet -p tacacsrs-agentd \
  --bin tacacsrs-agentd --locked -- supervision_tests::
mkdir executables/tacacsrs_agentd/.notification-fixtures
env -u NOTIFY_SOCKET TMPDIR=/proc/self/cwd/.notification-fixtures \
  cargo +stable test --quiet -p tacacsrs-agentd --test process_lifecycle --locked \
  -- shutdown_budget_terminates_a_stalled_systemd_helper --nocapture
rmdir executables/tacacsrs_agentd/.notification-fixtures
```

Results: 10 host tests, 15 supervision tests, and one native process test pass.
No tests fail or remain ignored.
They filter out 62, 57, and eight unrelated tests.
Cargo starts the native test in its package directory.
The `/proc/self/cwd` alias keeps its owned fixture path absolute and within the Unix socket length limit.
Two earlier fixture attempts failed before the shutdown assertion: one missing directory and one rejected relative endpoint.
Neither attempt supports the lifetime claim.

These prototype quality checks also exit 0 in the same shell:

```bash
cargo +nightly fmt --manifest-path experiments/systemd-notifications/Cargo.toml -- --check
cargo +nightly clippy --quiet --locked --manifest-path experiments/systemd-notifications/Cargo.toml \
  --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +stable doc --quiet --locked \
  --manifest-path experiments/systemd-notifications/Cargo.toml --no-deps --document-private-items
```

Integration requires document and link validation only.
No rejected dependencies enter integration, so no integration dependency audit, unused-dependency check, or freshness check applies.
No hosted platform build, SONiC VM run, live manager attribution test, Miri result, or full-workspace gate is claimed.
The probe uses safe Rust and Python. Native syscall behavior here requires Linux and real private sockets.
