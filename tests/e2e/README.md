# Black-Box End-to-End Tests (`tests/e2e`)

This `pytest` suite exercises compiled Linux binaries (`tacacsrs-agentd`, `tacacsrs-agent-health`, and `tacon`) as external OS processes alongside real dependencies such as `redis-server`, `openssl`, Unix domain sockets, POSIX signals, and `systemd-notify` helpers.

Wire-level fault injection, TLS/PSK state-machine edge cases, and high-concurrency multiplexing bursts stay in Rust using `libraries/tacacsrs_testkit`. Process orchestration, environment wiring, ConfigDB mutations, and CLI workflows belong here.

## Running locally

```bash
# Automatically builds debug binaries if needed and runs all E2E scenarios
python3 -m pytest -v tests/e2e

# Point at prebuilt release or cross-compiled binaries (used in CI and ARMhf QEMU)
python3 -m pytest -v tests/e2e --bin-dir target/release
```
