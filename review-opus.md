# Code Review — Round 4: `feature/yang-config-support` vs `main`

**Scope**: ~3,100 new lines across 29 files. Major additions: RPK client auth (`tls_rpk/` transport module), resolver submodules (`resolvers/{mod,tls,rpk,epsk}.rs`), TLS certificate-based server config, disable-cert-verification wiring, expanded validation + tests.

---

## Previous Findings Status

| # | Finding | R3 Status | R4 Status | Notes |
|---|---------|-----------|-----------|-------|
| R1-1 | CA certificates silently discarded | ✅ Fixed | ✅ Fixed | `build_root_cert_store()` in `config_connect.rs:307-344` correctly loads CA and EE certs into `RootCertStore`. |
| R1-2 | `domain_name`/`sni_enabled` ignored at TLS | ✅ Fixed | ✅ Fixed | `derive_sni_name()` uses `domain_name` when `sni_enabled`, both cert-TLS and RPK paths. Unit tests cover both branches. |
| R1-3 | Credential-reference resolver no-op stub | ✅ Fixed | ✅ Fixed | `NoOpResolver` now returns `Err(...)` for every method, not `Ok(None)`. External refs always fail without a resolver. |
| R1-4 | IPv6 address parsing broken | ✅ Fixed | ✅ Fixed | `socket_address()` at `resolvers/mod.rs:308-313` brackets any address containing `:`. Correct `[2001:db8::1]:49` output. |
| R1-5 | `raw_private_key` client identity silently dropped | ⚠️ Partial | ✅ Fixed | New `tls_rpk/` module handles RPK when `feature = "rpk"` is enabled. Without the feature, `config_connect.rs:64-69` bails explicitly. |
| R1-6 | Secrets in `Debug` output | ✅ Fixed | ✅ Fixed | `ResolvedServer::Debug` redacts `client_identity`, `server_authentication`, and `shared_secret`. `RpkIdentity::Debug` redacts key bytes. |
| R1-7 | `server-type` never used for routing | ❌ Still present | ❌ Still present | `server_type` is parsed, validated, and stored but never consulted for routing/failover decisions. Routing is purely positional (`active_index`). Low severity — acceptable if all servers handle all request types. |
| R1-8 | `ee_certs` inner choice not validated | ✅ Fixed | ✅ Fixed | Choice validation present in `validation.rs:210-220`. |
| R1-9 | Example JSON malformed | ✅ Fixed | ✅ Fixed | README examples are valid JSON with correct structure. |
| N1 | External resolver `None` leaves unresolved refs | ✅ Fixed | ✅ Fixed | `effective_resolver()` substitutes `NoOpResolver` which rejects all lookups. |
| N4 | `tls13_epsks` flag ignored in connection | ❌ Still present | ⚠️ Accepted | `server_authentication.tls13_epsks` is a boolean flag in the YANG model. Connection selection is driven by `client_identity.tls13_epsk` (the actual key material). The flag serves as validation metadata, not a connection selector. Acceptable design but should be documented. |
| N5 | TLS setup duplicated 3× | ✅ Fixed | ✅ Fixed | All connection setup centralised in `config_connect.rs::establish_stream()`. Both `tacon` and `tacacsrs_agent` use it. |
| N6 | `Deref` exposes `shared_secret` | ❌ Accepted | ❌ Accepted | `ResolvedServer` implements `Deref<Target = TacacsPlusServer>`, exposing `shared_secret`. Mitigated by `Debug` redaction and `obfuscation_key()` accessor. Accepted trade-off for ergonomic field access. |
| N8 | `too_many_lines` in agentd | ⚠️ Reduced | ✅ Fixed | `main.rs` split into `servers_from_cli`, `tls_cert_servers_from_cli`, `base_server_from_address`, `servers_from_config`. Well-structured now. |
| N9 | `from_raw` naming | ❌ Low priority | ❌ Low priority | `ResolvedServer::from_raw()` retains its name. Documented with a clear doc-comment. Acceptable. |
| GPT-N1 | External refs unusable from shipped binaries | ❌ Hardcoded `None` | ❌ Still present | Both `tacon` and `tacacsrs-agentd` pass `None` as the credential resolver when loading YANG configs. External keystore/truststore references will fail at resolution time via `NoOpResolver`. This is now a clear error rather than silent data loss, but the feature remains unusable without a custom binary. |
| GPT-N2 | `--insecure` flag regressed in agentd | ⚠️ Partial | ⚠️ Partial | See **R4-N1** below. The flag works for CLI-mode but is blocked by `conflicts_with_all` when using `--config`. |
| GPT-N3 | Cert keystore resolves only key, not cert | ❌ Still present | ✅ Fixed | `resolve_keystore_certificate()` in `tls.rs:17-53` now returns `X509CertificateMaterial` containing both `cert_data` and `key_material`. Both are populated into `inline_definition`. |
| GPT-N4 | README documents wrong `CredentialRefType` enum | ❌ | ✅ Fixed | README no longer mentions `CredentialRefType`. Documents `CredentialResolver` trait, material structs, and identity set enums correctly. |
| R3-N1 | `socket_address()` invalid IPv6 output | New | ✅ Fixed | `resolvers/mod.rs:309-310`: `format!("[{}]:{}", self.0.address, self.0.port)` — correct bracketed IPv6 output. |
| R3-N2 | `CredentialResolver::validate()` default treats `Ok(None)` as success | New | ✅ Fixed | No default method exists on the trait — all methods are abstract. All resolve callsites use `.ok_or_else(...)` to convert `Ok(None)` to error. `NoOpResolver` returns `Err(...)` unconditionally. |
| R3-N3 | RPK rejected at connection not validation | New | ✅ Fixed | Validation checks RPK choice constraints in `validation.rs:147-157`. Connection layer also validates: without `rpk` feature → bail at `config_connect.rs:64-69`; with feature → full RPK handshake via `tls_rpk/`. |
| R3-N4 | Agent daemon never passes `--insecure` to upstream | New | ✅ Fixed | `main.rs:310` passes `cli.insecure_disable_certificate_verification` into `ServiceConfig`. `upstream.rs:141,153` forwards it into `ConnectOptions`. |
| R3-N5 | Dead allocation in `connect_upstream` | New | ✅ Fixed | `upstream.rs:311-315`: `obfuscation_key` only computed for non-TLS servers. No wasted allocation. |
| R3-N6 | `get_server_addresses` mishandles bare IPv6 | New | ⚠️ Still present | See **R4-N2** below. |
| R3-N7 | README `CredentialRefType` wrong | Same as GPT-N4 | ✅ Fixed | See GPT-N4. |

### Summary: 19 of 25 findings fully resolved. 3 accepted trade-offs. 3 items remain (1 partial, 2 present).

---

## New Findings (Round 4)

### R4-N1: `--config` + `--insecure` mutually exclusive in agentd [Medium]

**File**: `executables/tacacsrs_agentd/src/main.rs:22-26`

```rust
#[arg(long, value_name = "FILE", conflicts_with_all = [
    "server_addresses", "shared_secret", "use_tls",
    "client_certificate", "client_key",
    "insecure_disable_certificate_verification",  // ← blocks --insecure with --config
])]
config: Option<PathBuf>,
```

The clap `conflicts_with_all` on `--config` includes `insecure_disable_certificate_verification`. This means an operator using YANG JSON config via `--config` **cannot** also pass `--insecure-disable-certificate-verification`. This is probably unintended — the `--insecure` flag should be orthogonal to the config source.

**Impact**: Operators using YANG config files with self-signed certs during development/testing cannot disable verification.

**Fix**: Remove `"insecure_disable_certificate_verification"` from the `conflicts_with_all` list. The flag applies to upstream TLS connections regardless of config source.

---

### R4-N2: `get_server_addresses` still mishandles bare IPv6 [Medium]

**File**: `libraries/tacacsrs_networking/src/helpers.rs:20-28`

```rust
pub fn get_server_addresses(hostname: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let address = if hostname.contains(':') {
        hostname.to_string()  // Bare IPv6 like "[2001:db8::1]:49" passes through
    } else {
        format!("{}:{}", hostname, 49)
    };
    let server_address_list: Vec<SocketAddr> = address.to_socket_addrs()?.collect();
    Ok(server_address_list)
}
```

This function is only called from `connect_tcp()`, which receives addresses from `socket_address()`. Since `socket_address()` now correctly brackets IPv6 (producing `[2001:db8::1]:49`), the **happy path works**. However, `get_server_addresses` is a `pub` API. Any caller passing a bare IPv6 address like `2001:db8::1` (no port, no brackets) hits the `contains(':')` branch, which treats the entire address as already having a port — then `to_socket_addrs()` fails because `2001:db8::1` is not a valid socket address string.

The `parse_host_port` function at lines 108-132 handles this correctly (detects multiple colons = IPv6). Consider using similar logic here, or making this function `pub(crate)` since `socket_address()` pre-formats addresses for `connect_tcp`.

---

### R4-N3: RPK path ignores `disable_certificate_verification` [Medium]

**File**: `libraries/tacacsrs_networking/src/config_connect.rs:122-141` and `config_builder.rs:201-256`

The RPK code path in `establish_stream` calls `establish_rpk_stream()` but **never passes `options.disable_certificate_verification`** to it. Compare with the certificate TLS path at line 200-201:

```rust
// Certificate TLS path:
if options.disable_certificate_verification {
    builder = builder.with_certificate_verification_disabled(true);
}

// RPK path (establish_rpk_stream): no such check
```

In `config_builder.rs:203-205`, when no pinned server keys are configured, verification is disabled automatically. But when pinned keys **are** present, there is no way for the user to override verification via `--insecure`. An operator cannot test against a server whose public key doesn't match.

**Fix**: Pass `disable_certificate_verification` to `establish_rpk_stream` and, when true, force `SslVerifyMode::NONE` regardless of pinned keys.

---

### R4-N4: RPK with no pinned keys silently disables server verification [Low]

**File**: `libraries/tacacsrs_networking/src/transport/tls_rpk/config_builder.rs:201-205`

```rust
if pinned_keys.is_empty() {
    // No pinned keys — disable server certificate verification.
    ctx_builder.set_verify(SslVerifyMode::NONE);
}
```

When `server_authentication.raw_public_keys` is absent or has no `inline_definition`, the RPK path silently sets `SslVerifyMode::NONE`. This is a security concern — the user may believe their connection is authenticated but no server verification occurs. At minimum, a `log::warn!` should be emitted. Consider whether this should require an explicit opt-in (like `--insecure`).

---

### R4-N5: `#[allow(unsafe_code)]` at module level in `tls_rpk/mod.rs` [Low]

**File**: `libraries/tacacsrs_networking/src/transport/tls_rpk/mod.rs:41`

```rust
#[allow(unsafe_code)]
mod config_builder;
```

The workspace forbids `unsafe_code` globally, but this module-level allow overrides it for the entire `config_builder` module. The actual `unsafe` is narrowly scoped to two FFI calls (lines 179-198). Consider using `#[allow(unsafe_code)]` on the specific `unsafe` blocks or the `create_rpk_ssl_context` function instead, to preserve the workspace-level safety guarantee for the rest of the module.

---

### R4-N6: Doc comment stale in `establish_stream` [Trivial]

**File**: `libraries/tacacsrs_networking/src/config_connect.rs:56`

```rust
/// - Raw private key (RPK) client auth is configured (not yet supported)
```

This error condition doc line says RPK is "not yet supported", but it **is** now supported behind the `rpk` feature flag. Update the doc to reflect the current state (e.g., "RPK requires the `rpk` feature flag").

---

### R4-N7: `unsafe` FFI calls lack soundness argument [Low]

**File**: `libraries/tacacsrs_networking/src/transport/tls_rpk/config_builder.rs:179-198`

The two `unsafe` blocks calling `SSL_CTX_set1_client_cert_type` and `SSL_CTX_set1_server_cert_type` have a comment at lines 172-175 explaining safety, but the `extern "C"` declarations at lines 26-37 declare the functions without `unsafe` keyword (they use `extern "C" { fn ... }` which makes them inherently unsafe to call). The FFI function signatures should be verified against the OpenSSL 3.2 headers:

1. The parameter types (`*mut SSL_CTX`, `*const u8`, `usize`) must match the C API exactly. OpenSSL declares the size parameter as `size_t` (which maps to `usize` on most platforms — correct).
2. The return type is `c_int` which matches OpenSSL's `int` return — correct.

The safety argument at lines 172-175 is sound but could be strengthened by noting that `SslContext::builder()`'s `as_ptr()` guarantees a non-null, valid `SSL_CTX*`.

---

### R4-N8: RPK fallthrough to cert-TLS when `cleartext_private_key` is `None` [Medium]

**File**: `libraries/tacacsrs_networking/src/config_connect.rs:124-141`

```rust
#[cfg(feature = "rpk")]
if let Some(ref ci) = server.client_identity {
    if let Some(ref rpk) = ci.raw_private_key {
        if let Some(ref inline) = rpk.inline_definition {
            if let Some(ref cleartext_key) = inline.cleartext_private_key {
                // ... RPK connection
                return Ok(BoxedTransport::new(tls_stream));
            }
        }
    }
}
```

If `raw_private_key` is configured but `cleartext_private_key` is `None` (e.g. `hidden_private_key` or `encrypted_private_key` is set instead, or the resolver returned a key without `cleartext_private_key`), the code **silently falls through** to the certificate-TLS path at line 143. This will likely result in a confusing TLS error rather than a clear message like "RPK configured but no cleartext private key available".

Validation in `validation.rs` checks that the inline definition exists and passes choice constraints, but does not enforce that `cleartext_private_key` is `Some`. A missing cleartext key with `hidden_private_key` present would pass validation but fail silently at connection time.

**Fix**: After the RPK `if let` chain, if `raw_private_key` is `Some` but we didn't enter the RPK path, bail with an explicit error.

---

## Overall Assessment

### What's Improved Since Round 3

The codebase has made significant progress. The major highlights:

1. **RPK support is real** — The `tls_rpk/` module is well-structured with proper FFI calls to OpenSSL 3.2+, DER key parsing for PKCS#1/SEC1/PKCS#8, server pin verification, and SNI support. The builder pattern is consistent with existing `TlsConfigurationBuilder` and `PskConfigurationBuilder`.

2. **Resolver architecture is clean** — Splitting `resolvers.rs` into `mod.rs` + `tls.rs` + `rpk.rs` + `epsk.rs` is a good separation of concerns. Each resolver submodule has both a resolve function (mutating) and a validate function (collect-all errors). The `NoOpResolver` pattern correctly prevents silent resolution failures.

3. **Connection setup is centralised** — `config_connect.rs::establish_stream()` is the single entry point, handling PSK → RPK → cert-TLS → TCP fallback. Both executables use it.

4. **Debug redaction is thorough** — `ResolvedServer::Debug`, `RpkIdentity::Debug` all redact secrets.

5. **Validation is comprehensive** — Choice constraints, key format validation, base64/PEM material checks, credential reference validation — all covered with extensive test suites.

### Remaining Concerns

| Priority | Finding | Impact |
|----------|---------|--------|
| Medium | R4-N1: `--config` + `--insecure` blocked | Operators can't disable cert verification with YANG config |
| Medium | R4-N3: RPK ignores `disable_certificate_verification` | `--insecure` has no effect on RPK connections |
| Medium | R4-N8: RPK silent fallthrough to cert-TLS | Confusing runtime errors when RPK key is not cleartext |
| Medium | R4-N2: `get_server_addresses` bare IPv6 | Pub API mishandles IPv6 without brackets (mitigated by `socket_address()` pre-formatting) |
| Low | R4-N4: RPK silently disables verification without pinned keys | Security: no warning when server not authenticated |
| Low | R4-N5: `#[allow(unsafe_code)]` scope too broad | Module-level allow weakens workspace safety guarantee |
| Low | R4-N7: FFI soundness argument could be stronger | Correctness: existing comment is adequate but minimal |
| Trivial | R4-N6: Stale doc comment | Says RPK "not yet supported" but it is now |

### Verdict

**Approve with requested changes** for R4-N1 (trivial clap fix), R4-N3 (wire `disable_certificate_verification` to RPK path), and R4-N8 (explicit error on RPK fallthrough). The remaining items are low priority and can be addressed in follow-up work.
