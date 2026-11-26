# Black-Box End-to-End Tests (`tests/e2e`)

This `pytest` suite exercises compiled Linux binaries (`tacacsrs-agentd`, `tacacsrs-agent-health`, and `tacon`) as external OS processes alongside real dependencies such as `redis-server`, `openssl`, Unix domain sockets, TCP proxy sockets, POSIX signals, and `systemd-notify` helpers.

## Scope and scenario files

Use `tests/e2e` for black-box multi-process workflows, live file and ConfigDB reloads, CLI interoperability, and end-to-end client-to-proxy-to-TLS-upstream behavior. Keep deterministic paused-clock unit tests and fine-grained internal state-machine checks in Rust (`#[cfg(test)]` and `libraries/tacacsrs_testkit`).

When adding a complex multi-actor scenario, place the scenario in its own `test_scenario_<name>.py` module and document the scenario at the top of the file before the test code:

- **Motivation**: Explain the operational risk or deployment behavior under test.
- **Topology**: Name the processes, listeners, credentials, and `tacacsrs:local-services` or `tacacsrs:runtime-policy` settings.
- **Expected sequence and outcomes**: List each step in order and state the observable wire, socket, health, and process outcomes that must hold.

Shared process, Redis, and PKI fixtures live in [`conftest.py`](./conftest.py). Minimal RFC 8907 framing, MD5 obfuscation, and TLS 1.3 upstream peer helpers live in [`tacacs_wire.py`](./tacacs_wire.py). Keep timing assertions compatible with slow emulated targets because CI runs this suite on both native AMD64 and QEMU ARMhf.

## Running locally

```bash
# Builds current debug binaries with Cargo and runs all E2E scenarios
python3 -m pytest -v tests/e2e

# Point at prebuilt release or cross-compiled binaries (used in CI and ARMhf QEMU)
python3 -m pytest -v tests/e2e --bin-dir target/release
```
