#!/usr/bin/env bash
set -euo pipefail

mkdir -p /evidence
exec > >(tee /evidence/verification.log) 2>&1
trap 'echo "ARMhf verification failed at line ${LINENO}" >&2' ERR

rustc --version --verbose
cargo --version
protoc --version
qemu-arm --version
test "${CARGO_BUILD_TARGET}" = armv7-unknown-linux-gnueabihf
find Cargo.toml Cargo.lock .cargo libraries executables lde .github/steps/armhf \
    -type f -print0 | sort -z | xargs -0 sha256sum > /evidence/SOURCE_SHA256SUMS

echo "==> Protobuf compiler selection regressions"
timeout --signal=TERM --kill-after=30s 20m \
    python3 .github/steps/armhf/test_protoc.py

echo "==> ARMhf release binaries"
timeout --signal=TERM --kill-after=30s 30m \
    cargo build --locked --release --bins \
        -p tacacsrs-agentd -p tacacsrs-agent-health -p tacon

echo "==> ARMhf unit and integration tests (including subprocess execution)"
timeout --signal=TERM --kill-after=30s 40m \
    cargo test --locked \
        -p tacacsrs-agentd -p tacacsrs-agent-health -p tacon \
        -p tacacsrs-sonic -p tacacsrs-ipc -p tacacsrs-agent-ipc-emulator \
        -- --test-threads=2

echo "==> Release binary ABI and execution"
for name in tacacsrs-agentd tacacsrs-agent-health tacon; do
    binary="${CARGO_TARGET_DIR}/${CARGO_BUILD_TARGET}/release/${name}"
    arm-linux-gnueabihf-readelf -h "${binary}" | tee "/evidence/${name}.elf"
    grep -Eq 'Class: +ELF32' "/evidence/${name}.elf"
    grep -Eq 'Machine: +ARM$' "/evidence/${name}.elf"
    grep -q 'hard-float ABI' "/evidence/${name}.elf"
    if grep -q 'soft-float ABI' "/evidence/${name}.elf"; then
        echo "${name} has the wrong floating-point ABI" >&2
        exit 1
    fi
    # Direct execution also verifies binfmt support for test-created subprocesses.
    timeout --signal=TERM --kill-after=5s 30s "${binary}" --help > "/evidence/${name}.help"
    test -s "/evidence/${name}.help"
    install -m 0755 "${binary}" "/evidence/${name}"
done
(cd /evidence && sha256sum tacacsrs-agentd tacacsrs-agent-health tacon > SHA256SUMS)
echo "ARMhf release build, executed tests, ABI, and startup checks passed."
