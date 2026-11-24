---
description: "Use for 32-bit musl builds, ARMhf containers, OpenSSL certificate dates, or ASN1_TIME_adj errors."
applyTo: "libraries/tacacsrs_networking/**,libraries/tacacsrs_kubesonic/**,executables/tacacsrs_agentd/**,.github/steps/**"
---

# Musl ABI validation

## Learnings

On 32-bit musl 1.2 or later, Rust libc and system OpenSSL must use the same 64-bit `time_t` ABI. A mismatch can produce `ASN1_TIME_adj:error getting time` or incorrect certificate validity results.

Set `--cfg=libc_unstable_musl_v1_2` in target `RUSTFLAGS`. Preserve the [networking ABI guard](../../libraries/tacacsrs_networking/src/lib.rs). Verify real certificate handshakes and date conversions on the executed ARMhf target.

```bash
RUSTFLAGS="-C target-feature=-crt-static --cfg=libc_unstable_musl_v1_2" \
  cargo build --target armv7-unknown-linux-musleabihf -p tacacsrs-agentd
```

A C-only OpenSSL provider probe does not verify Rust FFI bindings. A build or PSK probe alone cannot establish certificate-based TLS compatibility.
